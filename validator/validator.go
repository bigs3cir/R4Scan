package validator

import (
	"fmt"
	"github.com/go-playground/validator/v10"
	"r4scan/http/v2ray"
	"reflect"
	"regexp"
	"strings"
)

var v *validator.Validate

func init() {

	v = validator.New()
	_ = v.RegisterValidation("vmessCipher", vmessCipher)
	_ = v.RegisterValidation("vmessExperiments", vmessExperiments)
	_ = v.RegisterValidation("httpStatusCode", httpStatusCode)
	v.RegisterTagNameFunc(func(field reflect.StructField) string {
		label := field.Tag.Get("errMsg")
		if label == "" {
			return field.Name
		}
		return field.Name + "{{$" + label + "$}}"
	})
}

func vmessCipher(fl validator.FieldLevel) bool {

	cipher := fl.Field().String()
	_, exist := v2ray.VMessCipherList[cipher]
	return exist
}

func vmessExperiments(fl validator.FieldLevel) bool {

	experiments := fl.Field().String()
	if experiments == "AuthenticatedLength" || experiments == "NoTerminationSignal" {
		return true
	}

	split := strings.Split(experiments, "|")
	if len(split) > 0 {
		for _, v := range split {
			if v != "AuthenticatedLength" && v != "NoTerminationSignal" {
				return false
			}
		}
		return true
	}

	return false
}

func httpStatusCode(fl validator.FieldLevel) bool {

	code := fl.Field().String()
	return regexp.MustCompile(`^[1-5]\d\d$`).MatchString(code)
}

func Validator(s interface{}) error {

	var errs []string
	err := v.Struct(s)

	if err != nil {

		for _, validationErrs := range err.(validator.ValidationErrors) {

			//field := validationErrs.StructField()
			regexpStr := `'.*\{\{\$(.*)\$\}\}.*'`
			match := regexp.MustCompile(regexpStr).FindStringSubmatch(validationErrs.Error())

			if len(match) != 2 {
				errs = append(errs, validationErrs.Error())
			} else {
				errs = append(errs, match[1])
			}

		}

		return fmt.Errorf(strings.Join(errs, "\n"))
	}

	return nil
}

func Var(field interface{}, tag string) error {

	return v.Var(field, tag)
}