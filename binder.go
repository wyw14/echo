// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2015 LabStack LLC and Echo contributors

package echo

import (
	"encoding"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
)

/**
	Following functions provide handful of methods for binding to Go native types from request query or path parameters.
    * QueryParamsBinder(c) - binds query parameters (source URL)
    * PathValuesBinder(c) - binds path parameters (source URL)
    * FormFieldBinder(c) - binds form fields (source URL + body)

	Example:
  ```go
  var length int64
  err := echo.QueryParamsBinder(c).Int64("length", &length).BindError()
  ```

	For every supported type there are following methods:
		* <Type>("param", &destination) - if parameter value exists then binds it to given destination of that type i.e Int64(...).
		* Must<Type>("param", &destination) - parameter value is required to exist, binds it to given destination of that type i.e MustInt64(...).
		* <Type>s("param", &destination) - (for slices) if parameter values exists then binds it to given destination of that type i.e Int64s(...).
		* Must<Type>s("param", &destination) - (for slices) parameter value is required to exist, binds it to given destination of that type i.e MustInt64s(...).

  for some slice types `BindWithDelimiter("param", &dest, ",")` supports splitting parameter values before type conversion is done
  i.e. URL `/api/search?id=1,2,3&id=1` can be bind to `[]int64{1,2,3,1}`

	`FailFast` flags binder to stop binding after first bind error during binder call chain. Enabled by default.
  `BindError()` returns first bind error from binder and resets errors in binder. Useful along with `FailFast()` method
		to do binding and returns on first problem
  `BindErrors()` returns all bind errors from binder and resets errors in binder.

	Types that are supported:
		* bool
		* float32
		* float64
		* int
		* int8
		* int16
		* int32
		* int64
		* uint
		* uint8/byte (does not support `bytes()`. Use BindUnmarshaler/CustomFunc to convert value from base64 etc to []byte{})
		* uint16
		* uint32
		* uint64
		* string
		* time
		* duration
		* BindUnmarshaler() interface
		* TextUnmarshaler() interface
		* JSONUnmarshaler() interface
		* UnixTime() - converts unix time (integer) to time.Time
		* UnixTimeMilli() - converts unix time with millisecond precision (integer) to time.Time
		* UnixTimeNano() - converts unix time with nanosecond precision (integer) to time.Time
	* CustomFunc() - callback function for your custom conversion logic. Signature `func(values []string) []error`
	* CustomType()/MustCustomType() - bind using the custom decoder registered for the destination type with RegisterTypeDecoder
*/

// BindingError represents an error that occurred while binding request data.
//
// Note: JSON serialization is handled by the MarshalJSON method below, not by the
// struct tags (which are kept for documentation). MarshalJSON emits {"field","message"}.
type BindingError struct {
	// Field is the field name where value binding failed
	Field string `json:"field"`
	*HTTPError
	// Values of parameter that failed to bind.
	Values []string `json:"-"`
}

// NewBindingError creates new instance of binding error
func NewBindingError(sourceParam string, values []string, message string, err error) error {
	return &BindingError{
		Field:     sourceParam,
		Values:    values,
		HTTPError: &HTTPError{Code: http.StatusBadRequest, Message: message, err: err},
	}
}

// Error returns error message
func (be *BindingError) Error() string {
	return fmt.Sprintf("%s, field=%s", be.HTTPError.Error(), be.Field)
}

// MarshalJSON implements json.Marshaler so that binding errors are serialized into
// a structured response (e.g. {"field":"id","message":"..."}) rather than being
// flattened to a generic message. DefaultHTTPErrorHandler routes errors that
// implement json.Marshaler through their own encoding.
func (be *BindingError) MarshalJSON() ([]byte, error) {
	message := be.Message
	if message == "" {
		message = http.StatusText(be.Code)
	}
	return json.Marshal(struct {
		Field   string `json:"field"`
		Message string `json:"message"`
	}{
		Field:   be.Field,
		Message: message,
	})
}

// FieldDecoderFunc is a custom decoder registered for a specific Go type with
// RegisterTypeDecoder. It turns the raw string values bound to one request
// field or parameter into the decoded Go value.
//
// The values slice contains:
//   - one element for scalar bindings (a single field/parameter occurrence),
//   - every repeated value (e.g. "?tag=a&tag=b") when the destination is the
//     registered type itself - named slice types included, so the decoder can
//     decide how to combine repeated occurrences,
//   - one element per destination element for []T/[N]T fields whose element type T
//     is registered.
//
// Raw values, including empty strings, are passed as-is. A decoder is therefore
// responsible for treating empty input as a zero value or as an error, matching
// the contract of BindUnmarshaler.
//
// Decoders are consulted only after the built-in scalar conversions and the
// BindUnmarshaler, bindMultipleUnmarshaler and encoding.TextUnmarshaler
// interfaces, so registering one never changes the behavior of types the binder
// already supports (see RegisterTypeDecoder for the type-safe entry point).
type FieldDecoderFunc func(values []string) (any, error)

// fieldDecoderRegistry maps a reflect.Type to its registered FieldDecoderFunc.
// Registration usually happens in init() but the map is safe for concurrent
// reads and writes at any time: per-request binding only reads while handlers
// may still register additional decoders.
var fieldDecoderRegistry sync.Map // reflect.Type -> FieldDecoderFunc

func registerFieldDecoder(typ reflect.Type, decoder FieldDecoderFunc) {
	if typ == nil {
		panic("echo: custom field decoder type cannot be nil")
	}
	if decoder == nil {
		panic("echo: custom field decoder function cannot be nil")
	}
	fieldDecoderRegistry.Store(typ, decoder)
}

func unregisterFieldDecoder(typ reflect.Type) {
	if typ == nil {
		return
	}
	fieldDecoderRegistry.Delete(typ)
}

// lookupFieldDecoder returns the decoder registered for typ.
func lookupFieldDecoder(typ reflect.Type) (FieldDecoderFunc, bool) {
	decoder, ok := fieldDecoderRegistry.Load(typ)
	if !ok {
		return nil, false
	}
	return decoder.(FieldDecoderFunc), true
}

var (
	fieldDecoderBindUnmarshalerType = reflect.TypeFor[BindUnmarshaler]()
	fieldDecoderTextUnmarshalerType = reflect.TypeFor[encoding.TextUnmarshaler]()
)

// typeHasFieldUnmarshaler reports whether t (or *t) implements one of the
// unmarshaler interfaces that the binder dispatches BEFORE the custom decoder
// registry. Composite element decoding must stay out of the way of such types
// to preserve the existing BindUnmarshaler/TextUnmarshaler behavior.
func typeHasFieldUnmarshaler(t reflect.Type) bool {
	if t.Implements(fieldDecoderBindUnmarshalerType) || reflect.PointerTo(t).Implements(fieldDecoderBindUnmarshalerType) {
		return true
	}
	if t.Implements(fieldDecoderTextUnmarshalerType) || reflect.PointerTo(t).Implements(fieldDecoderTextUnmarshalerType) {
		return true
	}
	return false
}

// isBuiltInBoundType reports whether t is one of the scalar types the binder
// converts with its built-in conversions. The registry must not shadow these
// conversions so that registering a decoder cannot change existing behavior
// (this mirrors bindValue, where the built-in type switch runs first). Named
// user types such as `type MyInt int` are NOT considered built-in even though
// their Kind is a scalar kind, so decoders can be registered for them.
func isBuiltInBoundType(t reflect.Type) bool {
	if t == reflect.TypeFor[time.Duration]() {
		return true
	}
	switch t.Kind() {
	case reflect.Bool,
		reflect.String,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return t.PkgPath() == ""
	}
	return false
}

// decodeRegisteredInto decodes raw values into an addressable, settable field
// using a previously registered decoder. It supports:
//   - T and *T when a decoder is registered for T (nil pointers are allocated and
//     the decoder receives every value),
//   - []T and *[]T when a decoder is registered for the element type T,
//   - [N]T and *[N]T; registered element decoders are used when present and
//     built-in scalar conversions otherwise.
//
// ok is false when no registered decoder applies, in which case callers fall
// back to their regular type conversion. Decoder errors are returned unwrapped
// so callers keep their own error envelope (field prefix, HTTP status, ...).
func decodeRegisteredInto(values []string, field reflect.Value) (bool, error) {
	if field.Kind() == reflect.Pointer {
		// a decoder registered for the exact pointer type receives all values
		if decoder, ok := lookupFieldDecoder(field.Type()); ok {
			if field.IsNil() {
				field.Set(reflect.New(field.Type().Elem()))
			}
			out, err := decoder(values)
			if err != nil {
				return true, err
			}
			if out != nil {
				field.Set(reflect.ValueOf(out))
			}
			return true, nil
		}
		if field.IsNil() {
			field.Set(reflect.New(field.Type().Elem()))
		}
		return decodeRegisteredInto(values, field.Elem())
	}

	// built-in scalar types keep their existing conversions everywhere; a
	// registered decoder can only extend the binder with new (user) types.
	if isBuiltInBoundType(field.Type()) {
		return false, nil
	}

	// a decoder registered for the field type itself receives all values at
	// once - this covers user types as well as named slice types such as
	// `type Tags []string` that want their own multi-value semantics.
	if decoder, ok := lookupFieldDecoder(field.Type()); ok {
		out, err := decoder(values)
		if err != nil {
			return true, err
		}
		if out != nil {
			field.Set(reflect.ValueOf(out))
		}
		return true, nil
	}

	switch field.Kind() {
	case reflect.Slice:
		return decodeRegisteredSlice(values, field)
	case reflect.Array:
		return decodeRegisteredArray(values, field)
	}
	return false, nil
}

// decodeRegisteredSlice handles []T fields where T has a registered decoder. It
// returns ok=false so the built-in slice conversion keeps handling built-in
// elements and elements implementing the unmarshaler interfaces.
func decodeRegisteredSlice(values []string, sliceField reflect.Value) (bool, error) {
	elemType := sliceField.Type().Elem()
	baseType := elemType
	if elemType.Kind() == reflect.Pointer {
		baseType = elemType.Elem()
	}
	if isBuiltInBoundType(baseType) || typeHasFieldUnmarshaler(baseType) {
		return false, nil
	}
	if _, ok := lookupFieldDecoder(baseType); !ok {
		return false, nil
	}

	slice := reflect.MakeSlice(sliceField.Type(), len(values), len(values))
	for i, raw := range values {
		if _, err := decodeRegisteredInto([]string{raw}, slice.Index(i)); err != nil {
			return true, err
		}
	}
	sliceField.Set(slice)
	return true, nil
}

// decodeRegisteredArray handles fixed-size [N]T fields. Element decoders are
// used when registered; otherwise elements go through the built-in scalar
// conversion, so plain [N]int and friends bind too. Extra values are an error.
func decodeRegisteredArray(values []string, arrayField reflect.Value) (bool, error) {
	arrayType := arrayField.Type()
	if len(values) > arrayType.Len() {
		return true, fmt.Errorf("too many values (%d) for array %s of length %d", len(values), arrayType, arrayType.Len())
	}

	elemType := arrayType.Elem()
	baseType := elemType
	if elemType.Kind() == reflect.Pointer {
		baseType = elemType.Elem()
	}
	_, elementDecoderRegistered := lookupFieldDecoder(baseType)
	if isBuiltInBoundType(baseType) || typeHasFieldUnmarshaler(baseType) {
		elementDecoderRegistered = false
	}

	for i, raw := range values {
		element := arrayField.Index(i) // addressable
		if elementDecoderRegistered {
			if _, err := decodeRegisteredInto([]string{raw}, element); err != nil {
				return true, err
			}
			continue
		}
		if err := setWithProperType(elemType.Kind(), raw, element); err != nil {
			return true, err
		}
	}
	return true, nil
}

// ValueBinder provides utility methods for binding query or path parameter to various Go built-in types
type ValueBinder struct {
	// ValueFunc is used to get single parameter (first) value from request
	ValueFunc func(sourceParam string) string
	// ValuesFunc is used to get all values for parameter from request. i.e. `/api/search?ids=1&ids=2`
	ValuesFunc func(sourceParam string) []string
	// ErrorFunc is used to create errors. Allows you to use your own error type, that for example marshals to your specific json response
	ErrorFunc func(sourceParam string, values []string, message string, internalError error) error
	errors    []error
	// failFast is flag for binding methods to return without attempting to bind when previous binding already failed
	failFast bool
}

// QueryParamsBinder creates query parameter value binder
func QueryParamsBinder(c *Context) *ValueBinder {
	return &ValueBinder{
		failFast:  true,
		ValueFunc: c.QueryParam,
		ValuesFunc: func(sourceParam string) []string {
			values, ok := c.QueryParams()[sourceParam]
			if !ok {
				return nil
			}
			return values
		},
		ErrorFunc: NewBindingError,
	}
}

// PathValuesBinder creates path parameter value binder
func PathValuesBinder(c *Context) *ValueBinder {
	return &ValueBinder{
		failFast:  true,
		ValueFunc: c.Param,
		ValuesFunc: func(sourceParam string) []string {
			// path parameter should not have multiple values so getting values does not make sense but lets not error out here
			value := c.Param(sourceParam)
			if value == "" {
				return nil
			}
			return []string{value}
		},
		ErrorFunc: NewBindingError,
	}
}

// FormFieldBinder creates form field value binder
// For all requests, FormFieldBinder parses the raw query from the URL and uses query params as form fields
//
// For POST, PUT, and PATCH requests, it also reads the request body, parses it
// as a form and uses query params as form fields. Request body parameters take precedence over URL query
// string values in r.Form.
//
// NB: when binding forms take note that this implementation uses standard library form parsing
// which parses form data from BOTH URL and BODY if content type is not MIMEMultipartForm
// See https://golang.org/pkg/net/http/#Request.ParseForm
func FormFieldBinder(c *Context) *ValueBinder {
	vb := &ValueBinder{
		failFast: true,
		ValueFunc: func(sourceParam string) string {
			return c.Request().FormValue(sourceParam)
		},
		ErrorFunc: NewBindingError,
	}
	vb.ValuesFunc = func(sourceParam string) []string {
		if c.Request().Form == nil {
			// this is same as `Request().FormValue()` does internally
			_, _ = c.MultipartForm() // we want to trigger c.request.ParseMultipartForm(c.formParseMaxMemory)
		}
		values, ok := c.Request().Form[sourceParam]
		if !ok {
			return nil
		}
		return values
	}

	return vb
}

// FailFast set internal flag to indicate if binding methods will return early (without binding) when previous bind failed
// NB: call this method before any other binding methods as it modifies binding methods behaviour
func (b *ValueBinder) FailFast(value bool) *ValueBinder {
	b.failFast = value
	return b
}

func (b *ValueBinder) setError(err error) {
	if b.errors == nil {
		b.errors = []error{err}
		return
	}
	b.errors = append(b.errors, err)
}

// BindError returns first seen bind error and resets/empties binder errors for further calls
func (b *ValueBinder) BindError() error {
	if b.errors == nil {
		return nil
	}
	err := b.errors[0]
	b.errors = nil // reset errors so next chain will start from zero
	return err
}

// BindErrors returns all bind errors and resets/empties binder errors for further calls
func (b *ValueBinder) BindErrors() []error {
	if b.errors == nil {
		return nil
	}
	errors := b.errors
	b.errors = nil // reset errors so next chain will start from zero
	return errors
}

// CustomFunc binds parameter values with Func. Func is called only when parameter values exist.
func (b *ValueBinder) CustomFunc(sourceParam string, customFunc func(values []string) []error) *ValueBinder {
	return b.customFunc(sourceParam, customFunc, false)
}

// MustCustomFunc requires parameter values to exist to bind with Func. Returns error when value does not exist.
func (b *ValueBinder) MustCustomFunc(sourceParam string, customFunc func(values []string) []error) *ValueBinder {
	return b.customFunc(sourceParam, customFunc, true)
}

func (b *ValueBinder) customFunc(sourceParam string, customFunc func(values []string) []error, valueMustExist bool) *ValueBinder {
	if b.failFast && b.errors != nil {
		return b
	}

	values := b.ValuesFunc(sourceParam)
	if len(values) == 0 {
		if valueMustExist {
			b.setError(b.ErrorFunc(sourceParam, []string{}, "required field value is empty", nil))
		}
		return b
	}
	if errs := customFunc(values); errs != nil {
		b.errors = append(b.errors, errs...)
	}
	return b
}

// CustomType binds parameter values into dest using the FieldDecoderFunc registered
// for dest's element type (see RegisterTypeDecoder). dest must be a non-nil pointer,
// for example `*MyType`, `*[]MyType` or `*[3]int`. When the parameter is absent dest is
// left untouched; use MustCustomType to require the parameter.
func (b *ValueBinder) CustomType(sourceParam string, dest any) *ValueBinder {
	return b.customType(sourceParam, dest, false)
}

// MustCustomType requires parameter values to exist and binds them into dest using the
// FieldDecoderFunc registered for dest's element type (see RegisterTypeDecoder).
// Returns an error when the parameter does not exist or no decoder is registered.
func (b *ValueBinder) MustCustomType(sourceParam string, dest any) *ValueBinder {
	return b.customType(sourceParam, dest, true)
}

func (b *ValueBinder) customType(sourceParam string, dest any, valueMustExist bool) *ValueBinder {
	if b.failFast && b.errors != nil {
		return b
	}

	values := b.ValuesFunc(sourceParam)
	if len(values) == 0 {
		if valueMustExist {
			b.setError(b.ErrorFunc(sourceParam, []string{}, "required field value is empty", nil))
		}
		return b
	}

	rv := reflect.ValueOf(dest)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		b.setError(b.ErrorFunc(sourceParam, values, fmt.Sprintf("custom type bind destination must be a non-nil pointer, got %T", dest), nil))
		return b
	}
	if ok, err := decodeRegisteredInto(values, rv.Elem()); err != nil {
		b.setError(b.ErrorFunc(sourceParam, values, "failed to bind field value with registered custom decoder", err))
	} else if !ok {
		b.setError(b.ErrorFunc(sourceParam, values, fmt.Sprintf("no custom field decoder registered for type %T", dest), nil))
	}
	return b
}

// String binds parameter to string variable
func (b *ValueBinder) String(sourceParam string, dest *string) *ValueBinder {
	if b.failFast && b.errors != nil {
		return b
	}

	value := b.ValueFunc(sourceParam)
	if value == "" {
		return b
	}
	*dest = value
	return b
}

// MustString requires parameter value to exist to bind to string variable. Returns error when value does not exist
func (b *ValueBinder) MustString(sourceParam string, dest *string) *ValueBinder {
	if b.failFast && b.errors != nil {
		return b
	}

	value := b.ValueFunc(sourceParam)
	if value == "" {
		b.setError(b.ErrorFunc(sourceParam, []string{value}, "required field value is empty", nil))
		return b
	}
	*dest = value
	return b
}

// Strings binds parameter values to slice of string
func (b *ValueBinder) Strings(sourceParam string, dest *[]string) *ValueBinder {
	if b.failFast && b.errors != nil {
		return b
	}

	value := b.ValuesFunc(sourceParam)
	if value == nil {
		return b
	}
	*dest = value
	return b
}

// MustStrings requires parameter values to exist to bind to slice of string variables. Returns error when value does not exist
func (b *ValueBinder) MustStrings(sourceParam string, dest *[]string) *ValueBinder {
	if b.failFast && b.errors != nil {
		return b
	}

	value := b.ValuesFunc(sourceParam)
	if value == nil {
		b.setError(b.ErrorFunc(sourceParam, []string{}, "required field value is empty", nil))
		return b
	}
	*dest = value
	return b
}

// BindUnmarshaler binds parameter to destination implementing BindUnmarshaler interface
func (b *ValueBinder) BindUnmarshaler(sourceParam string, dest BindUnmarshaler) *ValueBinder {
	if b.failFast && b.errors != nil {
		return b
	}

	tmp := b.ValueFunc(sourceParam)
	if tmp == "" {
		return b
	}

	if err := dest.UnmarshalParam(tmp); err != nil {
		b.setError(b.ErrorFunc(sourceParam, []string{tmp}, "failed to bind field value to BindUnmarshaler interface", err))
	}
	return b
}

// MustBindUnmarshaler requires parameter value to exist to bind to destination implementing BindUnmarshaler interface.
// Returns error when value does not exist
func (b *ValueBinder) MustBindUnmarshaler(sourceParam string, dest BindUnmarshaler) *ValueBinder {
	if b.failFast && b.errors != nil {
		return b
	}

	value := b.ValueFunc(sourceParam)
	if value == "" {
		b.setError(b.ErrorFunc(sourceParam, []string{value}, "required field value is empty", nil))
		return b
	}

	if err := dest.UnmarshalParam(value); err != nil {
		b.setError(b.ErrorFunc(sourceParam, []string{value}, "failed to bind field value to BindUnmarshaler interface", err))
	}
	return b
}

// JSONUnmarshaler binds parameter to destination implementing json.Unmarshaler interface
func (b *ValueBinder) JSONUnmarshaler(sourceParam string, dest json.Unmarshaler) *ValueBinder {
	if b.failFast && b.errors != nil {
		return b
	}

	tmp := b.ValueFunc(sourceParam)
	if tmp == "" {
		return b
	}

	if err := dest.UnmarshalJSON([]byte(tmp)); err != nil {
		b.setError(b.ErrorFunc(sourceParam, []string{tmp}, "failed to bind field value to json.Unmarshaler interface", err))
	}
	return b
}

// MustJSONUnmarshaler requires parameter value to exist to bind to destination implementing json.Unmarshaler interface.
// Returns error when value does not exist
func (b *ValueBinder) MustJSONUnmarshaler(sourceParam string, dest json.Unmarshaler) *ValueBinder {
	if b.failFast && b.errors != nil {
		return b
	}

	tmp := b.ValueFunc(sourceParam)
	if tmp == "" {
		b.setError(b.ErrorFunc(sourceParam, []string{tmp}, "required field value is empty", nil))
		return b
	}

	if err := dest.UnmarshalJSON([]byte(tmp)); err != nil {
		b.setError(b.ErrorFunc(sourceParam, []string{tmp}, "failed to bind field value to json.Unmarshaler interface", err))
	}
	return b
}

// TextUnmarshaler binds parameter to destination implementing encoding.TextUnmarshaler interface
func (b *ValueBinder) TextUnmarshaler(sourceParam string, dest encoding.TextUnmarshaler) *ValueBinder {
	if b.failFast && b.errors != nil {
		return b
	}

	tmp := b.ValueFunc(sourceParam)
	if tmp == "" {
		return b
	}

	if err := dest.UnmarshalText([]byte(tmp)); err != nil {
		b.setError(b.ErrorFunc(sourceParam, []string{tmp}, "failed to bind field value to encoding.TextUnmarshaler interface", err))
	}
	return b
}

// MustTextUnmarshaler requires parameter value to exist to bind to destination implementing encoding.TextUnmarshaler interface.
// Returns error when value does not exist
func (b *ValueBinder) MustTextUnmarshaler(sourceParam string, dest encoding.TextUnmarshaler) *ValueBinder {
	if b.failFast && b.errors != nil {
		return b
	}

	tmp := b.ValueFunc(sourceParam)
	if tmp == "" {
		b.setError(b.ErrorFunc(sourceParam, []string{tmp}, "required field value is empty", nil))
		return b
	}

	if err := dest.UnmarshalText([]byte(tmp)); err != nil {
		b.setError(b.ErrorFunc(sourceParam, []string{tmp}, "failed to bind field value to encoding.TextUnmarshaler interface", err))
	}
	return b
}

// BindWithDelimiter binds parameter to destination by suitable conversion function.
// Delimiter is used before conversion to split parameter value to separate values
func (b *ValueBinder) BindWithDelimiter(sourceParam string, dest any, delimiter string) *ValueBinder {
	return b.bindWithDelimiter(sourceParam, dest, delimiter, false)
}

// MustBindWithDelimiter requires parameter value to exist to bind destination by suitable conversion function.
// Delimiter is used before conversion to split parameter value to separate values
func (b *ValueBinder) MustBindWithDelimiter(sourceParam string, dest any, delimiter string) *ValueBinder {
	return b.bindWithDelimiter(sourceParam, dest, delimiter, true)
}

func (b *ValueBinder) bindWithDelimiter(sourceParam string, dest any, delimiter string, valueMustExist bool) *ValueBinder {
	if b.failFast && b.errors != nil {
		return b
	}
	values := b.ValuesFunc(sourceParam)
	if len(values) == 0 {
		if valueMustExist {
			b.setError(b.ErrorFunc(sourceParam, []string{}, "required field value is empty", nil))
		}
		return b
	}
	tmpValues := make([]string, 0, len(values))
	for _, v := range values {
		tmpValues = append(tmpValues, strings.Split(v, delimiter)...)
	}

	switch d := dest.(type) {
	case *[]string:
		*d = tmpValues
		return b
	case *[]bool:
		return b.bools(sourceParam, tmpValues, d)
	case *[]int64, *[]int32, *[]int16, *[]int8, *[]int:
		return b.ints(sourceParam, tmpValues, d)
	case *[]uint64, *[]uint32, *[]uint16, *[]uint8, *[]uint: // *[]byte is same as *[]uint8
		return b.uints(sourceParam, tmpValues, d)
	case *[]float64, *[]float32:
		return b.floats(sourceParam, tmpValues, d)
	case *[]time.Duration:
		return b.durations(sourceParam, tmpValues, d)
	default:
		// support only cases when destination is slice
		// does not support time.Time as it needs argument (layout) for parsing or BindUnmarshaler
		b.setError(b.ErrorFunc(sourceParam, []string{}, "unsupported bind type", nil))
		return b
	}
}

// Int64 binds parameter to int64 variable
func (b *ValueBinder) Int64(sourceParam string, dest *int64) *ValueBinder {
	return b.intValue(sourceParam, dest, 64, false)
}

// MustInt64 requires parameter value to exist to bind to int64 variable. Returns error when value does not exist
func (b *ValueBinder) MustInt64(sourceParam string, dest *int64) *ValueBinder {
	return b.intValue(sourceParam, dest, 64, true)
}

// Int32 binds parameter to int32 variable
func (b *ValueBinder) Int32(sourceParam string, dest *int32) *ValueBinder {
	return b.intValue(sourceParam, dest, 32, false)
}

// MustInt32 requires parameter value to exist to bind to int32 variable. Returns error when value does not exist
func (b *ValueBinder) MustInt32(sourceParam string, dest *int32) *ValueBinder {
	return b.intValue(sourceParam, dest, 32, true)
}

// Int16 binds parameter to int16 variable
func (b *ValueBinder) Int16(sourceParam string, dest *int16) *ValueBinder {
	return b.intValue(sourceParam, dest, 16, false)
}

// MustInt16 requires parameter value to exist to bind to int16 variable. Returns error when value does not exist
func (b *ValueBinder) MustInt16(sourceParam string, dest *int16) *ValueBinder {
	return b.intValue(sourceParam, dest, 16, true)
}

// Int8 binds parameter to int8 variable
func (b *ValueBinder) Int8(sourceParam string, dest *int8) *ValueBinder {
	return b.intValue(sourceParam, dest, 8, false)
}

// MustInt8 requires parameter value to exist to bind to int8 variable. Returns error when value does not exist
func (b *ValueBinder) MustInt8(sourceParam string, dest *int8) *ValueBinder {
	return b.intValue(sourceParam, dest, 8, true)
}

// Int binds parameter to int variable
func (b *ValueBinder) Int(sourceParam string, dest *int) *ValueBinder {
	return b.intValue(sourceParam, dest, 0, false)
}

// MustInt requires parameter value to exist to bind to int variable. Returns error when value does not exist
func (b *ValueBinder) MustInt(sourceParam string, dest *int) *ValueBinder {
	return b.intValue(sourceParam, dest, 0, true)
}

func (b *ValueBinder) intValue(sourceParam string, dest any, bitSize int, valueMustExist bool) *ValueBinder {
	if b.failFast && b.errors != nil {
		return b
	}

	value := b.ValueFunc(sourceParam)
	if value == "" {
		if valueMustExist {
			b.setError(b.ErrorFunc(sourceParam, []string{}, "required field value is empty", nil))
		}
		return b
	}

	return b.int(sourceParam, value, dest, bitSize)
}

func (b *ValueBinder) int(sourceParam string, value string, dest any, bitSize int) *ValueBinder {
	n, err := strconv.ParseInt(value, 10, bitSize)
	if err != nil {
		if bitSize == 0 {
			b.setError(b.ErrorFunc(sourceParam, []string{value}, "failed to bind field value to int", err))
		} else {
			b.setError(b.ErrorFunc(sourceParam, []string{value}, fmt.Sprintf("failed to bind field value to int%v", bitSize), err))
		}
		return b
	}

	switch d := dest.(type) {
	case *int64:
		*d = n
	case *int32:
		*d = int32(n) // #nosec G115
	case *int16:
		*d = int16(n) // #nosec G115
	case *int8:
		*d = int8(n) // #nosec G115
	case *int:
		*d = int(n)
	}
	return b
}

func (b *ValueBinder) intsValue(sourceParam string, dest any, valueMustExist bool) *ValueBinder {
	if b.failFast && b.errors != nil {
		return b
	}

	values := b.ValuesFunc(sourceParam)
	if len(values) == 0 {
		if valueMustExist {
			b.setError(b.ErrorFunc(sourceParam, values, "required field value is empty", nil))
		}
		return b
	}
	return b.ints(sourceParam, values, dest)
}

func (b *ValueBinder) ints(sourceParam string, values []string, dest any) *ValueBinder {
	switch d := dest.(type) {
	case *[]int64:
		tmp := make([]int64, len(values))
		for i, v := range values {
			b.int(sourceParam, v, &tmp[i], 64)
			if b.failFast && b.errors != nil {
				return b
			}
		}
		if b.errors == nil {
			*d = tmp
		}
	case *[]int32:
		tmp := make([]int32, len(values))
		for i, v := range values {
			b.int(sourceParam, v, &tmp[i], 32)
			if b.failFast && b.errors != nil {
				return b
			}
		}
		if b.errors == nil {
			*d = tmp
		}
	case *[]int16:
		tmp := make([]int16, len(values))
		for i, v := range values {
			b.int(sourceParam, v, &tmp[i], 16)
			if b.failFast && b.errors != nil {
				return b
			}
		}
		if b.errors == nil {
			*d = tmp
		}
	case *[]int8:
		tmp := make([]int8, len(values))
		for i, v := range values {
			b.int(sourceParam, v, &tmp[i], 8)
			if b.failFast && b.errors != nil {
				return b
			}
		}
		if b.errors == nil {
			*d = tmp
		}
	case *[]int:
		tmp := make([]int, len(values))
		for i, v := range values {
			b.int(sourceParam, v, &tmp[i], 0)
			if b.failFast && b.errors != nil {
				return b
			}
		}
		if b.errors == nil {
			*d = tmp
		}
	}
	return b
}

// Int64s binds parameter to slice of int64
func (b *ValueBinder) Int64s(sourceParam string, dest *[]int64) *ValueBinder {
	return b.intsValue(sourceParam, dest, false)
}

// MustInt64s requires parameter value to exist to bind to int64 slice variable. Returns error when value does not exist
func (b *ValueBinder) MustInt64s(sourceParam string, dest *[]int64) *ValueBinder {
	return b.intsValue(sourceParam, dest, true)
}

// Int32s binds parameter to slice of int32
func (b *ValueBinder) Int32s(sourceParam string, dest *[]int32) *ValueBinder {
	return b.intsValue(sourceParam, dest, false)
}

// MustInt32s requires parameter value to exist to bind to int32 slice variable. Returns error when value does not exist
func (b *ValueBinder) MustInt32s(sourceParam string, dest *[]int32) *ValueBinder {
	return b.intsValue(sourceParam, dest, true)
}

// Int16s binds parameter to slice of int16
func (b *ValueBinder) Int16s(sourceParam string, dest *[]int16) *ValueBinder {
	return b.intsValue(sourceParam, dest, false)
}

// MustInt16s requires parameter value to exist to bind to int16 slice variable. Returns error when value does not exist
func (b *ValueBinder) MustInt16s(sourceParam string, dest *[]int16) *ValueBinder {
	return b.intsValue(sourceParam, dest, true)
}

// Int8s binds parameter to slice of int8
func (b *ValueBinder) Int8s(sourceParam string, dest *[]int8) *ValueBinder {
	return b.intsValue(sourceParam, dest, false)
}

// MustInt8s requires parameter value to exist to bind to int8 slice variable. Returns error when value does not exist
func (b *ValueBinder) MustInt8s(sourceParam string, dest *[]int8) *ValueBinder {
	return b.intsValue(sourceParam, dest, true)
}

// Ints binds parameter to slice of int
func (b *ValueBinder) Ints(sourceParam string, dest *[]int) *ValueBinder {
	return b.intsValue(sourceParam, dest, false)
}

// MustInts requires parameter value to exist to bind to int slice variable. Returns error when value does not exist
func (b *ValueBinder) MustInts(sourceParam string, dest *[]int) *ValueBinder {
	return b.intsValue(sourceParam, dest, true)
}

// Uint64 binds parameter to uint64 variable
func (b *ValueBinder) Uint64(sourceParam string, dest *uint64) *ValueBinder {
	return b.uintValue(sourceParam, dest, 64, false)
}

// MustUint64 requires parameter value to exist to bind to uint64 variable. Returns error when value does not exist
func (b *ValueBinder) MustUint64(sourceParam string, dest *uint64) *ValueBinder {
	return b.uintValue(sourceParam, dest, 64, true)
}

// Uint32 binds parameter to uint32 variable
func (b *ValueBinder) Uint32(sourceParam string, dest *uint32) *ValueBinder {
	return b.uintValue(sourceParam, dest, 32, false)
}

// MustUint32 requires parameter value to exist to bind to uint32 variable. Returns error when value does not exist
func (b *ValueBinder) MustUint32(sourceParam string, dest *uint32) *ValueBinder {
	return b.uintValue(sourceParam, dest, 32, true)
}

// Uint16 binds parameter to uint16 variable
func (b *ValueBinder) Uint16(sourceParam string, dest *uint16) *ValueBinder {
	return b.uintValue(sourceParam, dest, 16, false)
}

// MustUint16 requires parameter value to exist to bind to uint16 variable. Returns error when value does not exist
func (b *ValueBinder) MustUint16(sourceParam string, dest *uint16) *ValueBinder {
	return b.uintValue(sourceParam, dest, 16, true)
}

// Uint8 binds parameter to uint8 variable
func (b *ValueBinder) Uint8(sourceParam string, dest *uint8) *ValueBinder {
	return b.uintValue(sourceParam, dest, 8, false)
}

// MustUint8 requires parameter value to exist to bind to uint8 variable. Returns error when value does not exist
func (b *ValueBinder) MustUint8(sourceParam string, dest *uint8) *ValueBinder {
	return b.uintValue(sourceParam, dest, 8, true)
}

// Byte binds parameter to byte variable
func (b *ValueBinder) Byte(sourceParam string, dest *byte) *ValueBinder {
	return b.uintValue(sourceParam, dest, 8, false)
}

// MustByte requires parameter value to exist to bind to byte variable. Returns error when value does not exist
func (b *ValueBinder) MustByte(sourceParam string, dest *byte) *ValueBinder {
	return b.uintValue(sourceParam, dest, 8, true)
}

// Uint binds parameter to uint variable
func (b *ValueBinder) Uint(sourceParam string, dest *uint) *ValueBinder {
	return b.uintValue(sourceParam, dest, 0, false)
}

// MustUint requires parameter value to exist to bind to uint variable. Returns error when value does not exist
func (b *ValueBinder) MustUint(sourceParam string, dest *uint) *ValueBinder {
	return b.uintValue(sourceParam, dest, 0, true)
}

func (b *ValueBinder) uintValue(sourceParam string, dest any, bitSize int, valueMustExist bool) *ValueBinder {
	if b.failFast && b.errors != nil {
		return b
	}

	value := b.ValueFunc(sourceParam)
	if value == "" {
		if valueMustExist {
			b.setError(b.ErrorFunc(sourceParam, []string{}, "required field value is empty", nil))
		}
		return b
	}

	return b.uint(sourceParam, value, dest, bitSize)
}

func (b *ValueBinder) uint(sourceParam string, value string, dest any, bitSize int) *ValueBinder {
	n, err := strconv.ParseUint(value, 10, bitSize)
	if err != nil {
		if bitSize == 0 {
			b.setError(b.ErrorFunc(sourceParam, []string{value}, "failed to bind field value to uint", err))
		} else {
			b.setError(b.ErrorFunc(sourceParam, []string{value}, fmt.Sprintf("failed to bind field value to uint%v", bitSize), err))
		}
		return b
	}

	switch d := dest.(type) {
	case *uint64:
		*d = n
	case *uint32:
		*d = uint32(n) // #nosec G115
	case *uint16:
		*d = uint16(n) // #nosec G115
	case *uint8: // byte is alias to uint8
		*d = uint8(n) // #nosec G115
	case *uint:
		*d = uint(n) // #nosec G115
	}
	return b
}

func (b *ValueBinder) uintsValue(sourceParam string, dest any, valueMustExist bool) *ValueBinder {
	if b.failFast && b.errors != nil {
		return b
	}

	values := b.ValuesFunc(sourceParam)
	if len(values) == 0 {
		if valueMustExist {
			b.setError(b.ErrorFunc(sourceParam, values, "required field value is empty", nil))
		}
		return b
	}
	return b.uints(sourceParam, values, dest)
}

func (b *ValueBinder) uints(sourceParam string, values []string, dest any) *ValueBinder {
	switch d := dest.(type) {
	case *[]uint64:
		tmp := make([]uint64, len(values))
		for i, v := range values {
			b.uint(sourceParam, v, &tmp[i], 64)
			if b.failFast && b.errors != nil {
				return b
			}
		}
		if b.errors == nil {
			*d = tmp
		}
	case *[]uint32:
		tmp := make([]uint32, len(values))
		for i, v := range values {
			b.uint(sourceParam, v, &tmp[i], 32)
			if b.failFast && b.errors != nil {
				return b
			}
		}
		if b.errors == nil {
			*d = tmp
		}
	case *[]uint16:
		tmp := make([]uint16, len(values))
		for i, v := range values {
			b.uint(sourceParam, v, &tmp[i], 16)
			if b.failFast && b.errors != nil {
				return b
			}
		}
		if b.errors == nil {
			*d = tmp
		}
	case *[]uint8: // byte is alias to uint8
		tmp := make([]uint8, len(values))
		for i, v := range values {
			b.uint(sourceParam, v, &tmp[i], 8)
			if b.failFast && b.errors != nil {
				return b
			}
		}
		if b.errors == nil {
			*d = tmp
		}
	case *[]uint:
		tmp := make([]uint, len(values))
		for i, v := range values {
			b.uint(sourceParam, v, &tmp[i], 0)
			if b.failFast && b.errors != nil {
				return b
			}
		}
		if b.errors == nil {
			*d = tmp
		}
	}
	return b
}

// Uint64s binds parameter to slice of uint64
func (b *ValueBinder) Uint64s(sourceParam string, dest *[]uint64) *ValueBinder {
	return b.uintsValue(sourceParam, dest, false)
}

// MustUint64s requires parameter value to exist to bind to uint64 slice variable. Returns error when value does not exist
func (b *ValueBinder) MustUint64s(sourceParam string, dest *[]uint64) *ValueBinder {
	return b.uintsValue(sourceParam, dest, true)
}

// Uint32s binds parameter to slice of uint32
func (b *ValueBinder) Uint32s(sourceParam string, dest *[]uint32) *ValueBinder {
	return b.uintsValue(sourceParam, dest, false)
}

// MustUint32s requires parameter value to exist to bind to uint32 slice variable. Returns error when value does not exist
func (b *ValueBinder) MustUint32s(sourceParam string, dest *[]uint32) *ValueBinder {
	return b.uintsValue(sourceParam, dest, true)
}

// Uint16s binds parameter to slice of uint16
func (b *ValueBinder) Uint16s(sourceParam string, dest *[]uint16) *ValueBinder {
	return b.uintsValue(sourceParam, dest, false)
}

// MustUint16s requires parameter value to exist to bind to uint16 slice variable. Returns error when value does not exist
func (b *ValueBinder) MustUint16s(sourceParam string, dest *[]uint16) *ValueBinder {
	return b.uintsValue(sourceParam, dest, true)
}

// Uint8s binds parameter to slice of uint8
func (b *ValueBinder) Uint8s(sourceParam string, dest *[]uint8) *ValueBinder {
	return b.uintsValue(sourceParam, dest, false)
}

// MustUint8s requires parameter value to exist to bind to uint8 slice variable. Returns error when value does not exist
func (b *ValueBinder) MustUint8s(sourceParam string, dest *[]uint8) *ValueBinder {
	return b.uintsValue(sourceParam, dest, true)
}

// Uints binds parameter to slice of uint
func (b *ValueBinder) Uints(sourceParam string, dest *[]uint) *ValueBinder {
	return b.uintsValue(sourceParam, dest, false)
}

// MustUints requires parameter value to exist to bind to uint slice variable. Returns error when value does not exist
func (b *ValueBinder) MustUints(sourceParam string, dest *[]uint) *ValueBinder {
	return b.uintsValue(sourceParam, dest, true)
}

// Bool binds parameter to bool variable
func (b *ValueBinder) Bool(sourceParam string, dest *bool) *ValueBinder {
	return b.boolValue(sourceParam, dest, false)
}

// MustBool requires parameter value to exist to bind to bool variable. Returns error when value does not exist
func (b *ValueBinder) MustBool(sourceParam string, dest *bool) *ValueBinder {
	return b.boolValue(sourceParam, dest, true)
}

func (b *ValueBinder) boolValue(sourceParam string, dest *bool, valueMustExist bool) *ValueBinder {
	if b.failFast && b.errors != nil {
		return b
	}

	value := b.ValueFunc(sourceParam)
	if value == "" {
		if valueMustExist {
			b.setError(b.ErrorFunc(sourceParam, []string{}, "required field value is empty", nil))
		}
		return b
	}
	return b.bool(sourceParam, value, dest)
}

func (b *ValueBinder) bool(sourceParam string, value string, dest *bool) *ValueBinder {
	n, err := strconv.ParseBool(value)
	if err != nil {
		b.setError(b.ErrorFunc(sourceParam, []string{value}, "failed to bind field value to bool", err))
		return b
	}

	*dest = n
	return b
}

func (b *ValueBinder) boolsValue(sourceParam string, dest *[]bool, valueMustExist bool) *ValueBinder {
	if b.failFast && b.errors != nil {
		return b
	}

	values := b.ValuesFunc(sourceParam)
	if len(values) == 0 {
		if valueMustExist {
			b.setError(b.ErrorFunc(sourceParam, []string{}, "required field value is empty", nil))
		}
		return b
	}
	return b.bools(sourceParam, values, dest)
}

func (b *ValueBinder) bools(sourceParam string, values []string, dest *[]bool) *ValueBinder {
	tmp := make([]bool, len(values))
	for i, v := range values {
		b.bool(sourceParam, v, &tmp[i])
		if b.failFast && b.errors != nil {
			return b
		}
	}
	if b.errors == nil {
		*dest = tmp
	}
	return b
}

// Bools binds parameter values to slice of bool variables
func (b *ValueBinder) Bools(sourceParam string, dest *[]bool) *ValueBinder {
	return b.boolsValue(sourceParam, dest, false)
}

// MustBools requires parameter values to exist to bind to slice of bool variables. Returns error when values does not exist
func (b *ValueBinder) MustBools(sourceParam string, dest *[]bool) *ValueBinder {
	return b.boolsValue(sourceParam, dest, true)
}

// Float64 binds parameter to float64 variable
func (b *ValueBinder) Float64(sourceParam string, dest *float64) *ValueBinder {
	return b.floatValue(sourceParam, dest, 64, false)
}

// MustFloat64 requires parameter value to exist to bind to float64 variable. Returns error when value does not exist
func (b *ValueBinder) MustFloat64(sourceParam string, dest *float64) *ValueBinder {
	return b.floatValue(sourceParam, dest, 64, true)
}

// Float32 binds parameter to float32 variable
func (b *ValueBinder) Float32(sourceParam string, dest *float32) *ValueBinder {
	return b.floatValue(sourceParam, dest, 32, false)
}

// MustFloat32 requires parameter value to exist to bind to float32 variable. Returns error when value does not exist
func (b *ValueBinder) MustFloat32(sourceParam string, dest *float32) *ValueBinder {
	return b.floatValue(sourceParam, dest, 32, true)
}

func (b *ValueBinder) floatValue(sourceParam string, dest any, bitSize int, valueMustExist bool) *ValueBinder {
	if b.failFast && b.errors != nil {
		return b
	}

	value := b.ValueFunc(sourceParam)
	if value == "" {
		if valueMustExist {
			b.setError(b.ErrorFunc(sourceParam, []string{}, "required field value is empty", nil))
		}
		return b
	}

	return b.float(sourceParam, value, dest, bitSize)
}

func (b *ValueBinder) float(sourceParam string, value string, dest any, bitSize int) *ValueBinder {
	n, err := strconv.ParseFloat(value, bitSize)
	if err != nil {
		b.setError(b.ErrorFunc(sourceParam, []string{value}, fmt.Sprintf("failed to bind field value to float%v", bitSize), err))
		return b
	}

	switch d := dest.(type) {
	case *float64:
		*d = n
	case *float32:
		*d = float32(n)
	}
	return b
}

func (b *ValueBinder) floatsValue(sourceParam string, dest any, valueMustExist bool) *ValueBinder {
	if b.failFast && b.errors != nil {
		return b
	}

	values := b.ValuesFunc(sourceParam)
	if len(values) == 0 {
		if valueMustExist {
			b.setError(b.ErrorFunc(sourceParam, []string{}, "required field value is empty", nil))
		}
		return b
	}
	return b.floats(sourceParam, values, dest)
}

func (b *ValueBinder) floats(sourceParam string, values []string, dest any) *ValueBinder {
	switch d := dest.(type) {
	case *[]float64:
		tmp := make([]float64, len(values))
		for i, v := range values {
			b.float(sourceParam, v, &tmp[i], 64)
			if b.failFast && b.errors != nil {
				return b
			}
		}
		if b.errors == nil {
			*d = tmp
		}
	case *[]float32:
		tmp := make([]float32, len(values))
		for i, v := range values {
			b.float(sourceParam, v, &tmp[i], 32)
			if b.failFast && b.errors != nil {
				return b
			}
		}
		if b.errors == nil {
			*d = tmp
		}
	}
	return b
}

// Float64s binds parameter values to slice of float64 variables
func (b *ValueBinder) Float64s(sourceParam string, dest *[]float64) *ValueBinder {
	return b.floatsValue(sourceParam, dest, false)
}

// MustFloat64s requires parameter values to exist to bind to slice of float64 variables. Returns error when values does not exist
func (b *ValueBinder) MustFloat64s(sourceParam string, dest *[]float64) *ValueBinder {
	return b.floatsValue(sourceParam, dest, true)
}

// Float32s binds parameter values to slice of float32 variables
func (b *ValueBinder) Float32s(sourceParam string, dest *[]float32) *ValueBinder {
	return b.floatsValue(sourceParam, dest, false)
}

// MustFloat32s requires parameter values to exist to bind to slice of float32 variables. Returns error when values does not exist
func (b *ValueBinder) MustFloat32s(sourceParam string, dest *[]float32) *ValueBinder {
	return b.floatsValue(sourceParam, dest, true)
}

// Time binds parameter to time.Time variable
func (b *ValueBinder) Time(sourceParam string, dest *time.Time, layout string) *ValueBinder {
	return b.time(sourceParam, dest, layout, false)
}

// MustTime requires parameter value to exist to bind to time.Time variable. Returns error when value does not exist
func (b *ValueBinder) MustTime(sourceParam string, dest *time.Time, layout string) *ValueBinder {
	return b.time(sourceParam, dest, layout, true)
}

func (b *ValueBinder) time(sourceParam string, dest *time.Time, layout string, valueMustExist bool) *ValueBinder {
	if b.failFast && b.errors != nil {
		return b
	}

	value := b.ValueFunc(sourceParam)
	if value == "" {
		if valueMustExist {
			b.setError(b.ErrorFunc(sourceParam, []string{value}, "required field value is empty", nil))
		}
		return b
	}
	t, err := time.Parse(layout, value)
	if err != nil {
		b.setError(b.ErrorFunc(sourceParam, []string{value}, "failed to bind field value to Time", err))
		return b
	}
	*dest = t
	return b
}

// Times binds parameter values to slice of time.Time variables
func (b *ValueBinder) Times(sourceParam string, dest *[]time.Time, layout string) *ValueBinder {
	return b.times(sourceParam, dest, layout, false)
}

// MustTimes requires parameter values to exist to bind to slice of time.Time variables. Returns error when values does not exist
func (b *ValueBinder) MustTimes(sourceParam string, dest *[]time.Time, layout string) *ValueBinder {
	return b.times(sourceParam, dest, layout, true)
}

func (b *ValueBinder) times(sourceParam string, dest *[]time.Time, layout string, valueMustExist bool) *ValueBinder {
	if b.failFast && b.errors != nil {
		return b
	}

	values := b.ValuesFunc(sourceParam)
	if len(values) == 0 {
		if valueMustExist {
			b.setError(b.ErrorFunc(sourceParam, []string{}, "required field value is empty", nil))
		}
		return b
	}

	tmp := make([]time.Time, len(values))
	for i, v := range values {
		t, err := time.Parse(layout, v)
		if err != nil {
			b.setError(b.ErrorFunc(sourceParam, []string{v}, "failed to bind field value to Time", err))
			if b.failFast {
				return b
			}
			continue
		}
		tmp[i] = t
	}
	if b.errors == nil {
		*dest = tmp
	}
	return b
}

// Duration binds parameter to time.Duration variable
func (b *ValueBinder) Duration(sourceParam string, dest *time.Duration) *ValueBinder {
	return b.duration(sourceParam, dest, false)
}

// MustDuration requires parameter value to exist to bind to time.Duration variable. Returns error when value does not exist
func (b *ValueBinder) MustDuration(sourceParam string, dest *time.Duration) *ValueBinder {
	return b.duration(sourceParam, dest, true)
}

func (b *ValueBinder) duration(sourceParam string, dest *time.Duration, valueMustExist bool) *ValueBinder {
	if b.failFast && b.errors != nil {
		return b
	}

	value := b.ValueFunc(sourceParam)
	if value == "" {
		if valueMustExist {
			b.setError(b.ErrorFunc(sourceParam, []string{value}, "required field value is empty", nil))
		}
		return b
	}
	t, err := time.ParseDuration(value)
	if err != nil {
		b.setError(b.ErrorFunc(sourceParam, []string{value}, "failed to bind field value to Duration", err))
		return b
	}
	*dest = t
	return b
}

// Durations binds parameter values to slice of time.Duration variables
func (b *ValueBinder) Durations(sourceParam string, dest *[]time.Duration) *ValueBinder {
	return b.durationsValue(sourceParam, dest, false)
}

// MustDurations requires parameter values to exist to bind to slice of time.Duration variables. Returns error when values does not exist
func (b *ValueBinder) MustDurations(sourceParam string, dest *[]time.Duration) *ValueBinder {
	return b.durationsValue(sourceParam, dest, true)
}

func (b *ValueBinder) durationsValue(sourceParam string, dest *[]time.Duration, valueMustExist bool) *ValueBinder {
	if b.failFast && b.errors != nil {
		return b
	}

	values := b.ValuesFunc(sourceParam)
	if len(values) == 0 {
		if valueMustExist {
			b.setError(b.ErrorFunc(sourceParam, []string{}, "required field value is empty", nil))
		}
		return b
	}
	return b.durations(sourceParam, values, dest)
}

func (b *ValueBinder) durations(sourceParam string, values []string, dest *[]time.Duration) *ValueBinder {
	tmp := make([]time.Duration, len(values))
	for i, v := range values {
		t, err := time.ParseDuration(v)
		if err != nil {
			b.setError(b.ErrorFunc(sourceParam, []string{v}, "failed to bind field value to Duration", err))
			if b.failFast {
				return b
			}
			continue
		}
		tmp[i] = t
	}
	if b.errors == nil {
		*dest = tmp
	}
	return b
}

// UnixTime binds parameter to time.Time variable (in local Time corresponding to the given Unix time).
//
// Example: 1609180603 bind to 2020-12-28T18:36:43.000000000+00:00
//
// Note:
//   - time.Time{} (param is empty) and time.Unix(0,0) (param = "0") are not equal
func (b *ValueBinder) UnixTime(sourceParam string, dest *time.Time) *ValueBinder {
	return b.unixTime(sourceParam, dest, false, time.Second)
}

// MustUnixTime requires parameter value to exist to bind to time.Time variable (in local time corresponding
// to the given Unix time). Returns error when value does not exist.
//
// Example: 1609180603 bind to 2020-12-28T18:36:43.000000000+00:00
//
// Note:
//   - time.Time{} (param is empty) and time.Unix(0,0) (param = "0") are not equal
func (b *ValueBinder) MustUnixTime(sourceParam string, dest *time.Time) *ValueBinder {
	return b.unixTime(sourceParam, dest, true, time.Second)
}

// UnixTimeMilli binds parameter to time.Time variable (in local time corresponding to the given Unix time in millisecond precision).
//
// Example: 1647184410140 bind to 2022-03-13T15:13:30.140000000+00:00
//
// Note:
//   - time.Time{} (param is empty) and time.Unix(0,0) (param = "0") are not equal
func (b *ValueBinder) UnixTimeMilli(sourceParam string, dest *time.Time) *ValueBinder {
	return b.unixTime(sourceParam, dest, false, time.Millisecond)
}

// MustUnixTimeMilli requires parameter value to exist to bind to time.Time variable (in local time corresponding
// to the given Unix time in millisecond precision). Returns error when value does not exist.
//
// Example: 1647184410140 bind to 2022-03-13T15:13:30.140000000+00:00
//
// Note:
//   - time.Time{} (param is empty) and time.Unix(0,0) (param = "0") are not equal
func (b *ValueBinder) MustUnixTimeMilli(sourceParam string, dest *time.Time) *ValueBinder {
	return b.unixTime(sourceParam, dest, true, time.Millisecond)
}

// UnixTimeNano binds parameter to time.Time variable (in local time corresponding to the given Unix time in nanosecond precision).
//
// Example: 1609180603123456789 binds to 2020-12-28T18:36:43.123456789+00:00
// Example:          1000000000 binds to 1970-01-01T00:00:01.000000000+00:00
// Example:           999999999 binds to 1970-01-01T00:00:00.999999999+00:00
//
// Note:
//   - time.Time{} (param is empty) and time.Unix(0,0) (param = "0") are not equal
//   - Javascript's Number type only has about 53 bits of precision (Number.MAX_SAFE_INTEGER = 9007199254740991). Compare it to 1609180603123456789 in example.
func (b *ValueBinder) UnixTimeNano(sourceParam string, dest *time.Time) *ValueBinder {
	return b.unixTime(sourceParam, dest, false, time.Nanosecond)
}

// MustUnixTimeNano requires parameter value to exist to bind to time.Time variable (in local time corresponding
// to the given Unix time value in nanosecond precision). Returns error when value does not exist.
//
// Example: 1609180603123456789 binds to 2020-12-28T18:36:43.123456789+00:00
// Example:          1000000000 binds to 1970-01-01T00:00:01.000000000+00:00
// Example:           999999999 binds to 1970-01-01T00:00:00.999999999+00:00
//
// Note:
//   - time.Time{} (param is empty) and time.Unix(0,0) (param = "0") are not equal
//   - Javascript's Number type only has about 53 bits of precision (Number.MAX_SAFE_INTEGER = 9007199254740991). Compare it to 1609180603123456789 in example.
func (b *ValueBinder) MustUnixTimeNano(sourceParam string, dest *time.Time) *ValueBinder {
	return b.unixTime(sourceParam, dest, true, time.Nanosecond)
}

func (b *ValueBinder) unixTime(sourceParam string, dest *time.Time, valueMustExist bool, precision time.Duration) *ValueBinder {
	if b.failFast && b.errors != nil {
		return b
	}

	value := b.ValueFunc(sourceParam)
	if value == "" {
		if valueMustExist {
			b.setError(b.ErrorFunc(sourceParam, []string{value}, "required field value is empty", nil))
		}
		return b
	}

	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		b.setError(b.ErrorFunc(sourceParam, []string{value}, "failed to bind field value to Time", err))
		return b
	}

	switch precision {
	case time.Second:
		*dest = time.Unix(n, 0)
	case time.Millisecond:
		*dest = time.UnixMilli(n)
	case time.Nanosecond:
		*dest = time.Unix(0, n)
	}
	return b
}
