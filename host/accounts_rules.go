package host

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Sign-up rules, mirrored from the Red-XAI Accounts v1 contract (docs/API.md "Rules"). The console shows the
// same checks live; redxd re-checks every field before anything is sent to Red-XAI Accounts, which checks again.

const (
	UsernameMin     = 8
	UsernameMax     = 32
	UsernameLetters = 3
	PasswordMin     = 12
	PasswordMax     = 665
	EmailMax        = 254
	NameMax         = 50
	CentralMinAge   = 13 // no Red-XAI app has under-13 accounts
	MaxAge          = 100
	// SafeSpecials are the special characters a password may (and must, at least once) use.
	SafeSpecials = "!#$%&()*+,-./:;=?@[]^_{|}~"
)

var (
	emailRe = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(\\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\.)+[A-Za-z]{2,63}$")
	dobRe   = regexp.MustCompile(`^(\d{2})/(\d{2})/(\d{4})$`)
	phoneRe = regexp.MustCompile(`^\+[1-9][0-9]{7,14}$`)
)

// RuleCheck is one live hint: red until OK, then green.
type RuleCheck struct {
	ID      string `json:"id"`
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

// FieldError is the first rule a sign-up breaks, with the contract's stable error code.
type FieldError struct {
	Code    string `json:"error"`
	Message string `json:"message"`
	Field   string `json:"field,omitempty"`
}

func (e *FieldError) Error() string { return e.Code + ": " + e.Message }

func isLetter(r rune) bool { return r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' }
func isDigit(r rune) bool  { return r >= '0' && r <= '9' }

// CheckUsername: 8–32 characters, only A–Z a–z 0–9 _ . -, at least 3 letters.
func CheckUsername(u string) []RuleCheck {
	n, letters, chars := 0, 0, true
	for _, r := range u {
		n++
		switch {
		case isLetter(r):
			letters++
		case isDigit(r) || r == '_' || r == '.' || r == '-':
		default:
			chars = false
		}
	}
	return []RuleCheck{
		{"length", n >= UsernameMin && n <= UsernameMax, fmt.Sprintf("%d to %d characters", UsernameMin, UsernameMax)},
		{"chars", chars && n > 0, "Only letters, numbers, _ . and -"},
		{"letters", letters >= UsernameLetters, fmt.Sprintf("At least %d letters", UsernameLetters)},
	}
}

// CheckPassword: 12–665 characters with an upper-case letter, a lower-case letter, a number and a safe special.
func CheckPassword(p string) []RuleCheck {
	n := 0
	var up, lo, dg, sp bool
	chars := true
	for _, r := range p {
		n++
		switch {
		case r >= 'A' && r <= 'Z':
			up = true
		case r >= 'a' && r <= 'z':
			lo = true
		case isDigit(r):
			dg = true
		case r < 128 && strings.ContainsRune(SafeSpecials, r):
			sp = true
		default:
			chars = false
		}
	}
	return []RuleCheck{
		{"length", n >= PasswordMin && n <= PasswordMax, fmt.Sprintf("%d to %d characters", PasswordMin, PasswordMax)},
		{"upper", up, "An upper-case letter (A–Z)"},
		{"lower", lo, "A lower-case letter (a–z)"},
		{"digit", dg, "A number (0–9)"},
		{"special", sp, "A special character: " + SafeSpecials},
		{"chars", chars && n > 0, "No spaces, quotes, backslashes, backticks or < >"},
	}
}

// isNamePunct is a space, apostrophe, hyphen or period (Accounts v1.2 name rules).
func isNamePunct(r rune) bool {
	switch r {
	case ' ', '\'', '-', '.', '’', '‐', '‑':
		return true
	default:
		return false
	}
}

// CheckName: 1–50 characters of letters (any script), spaces, apostrophes, hyphens and periods,
// with at least one letter. An empty optional name (middle) passes.
func CheckName(s string, required bool) []RuleCheck {
	s = strings.TrimSpace(s)
	if !required && s == "" {
		return []RuleCheck{
			{"length", true, "Optional — 1 to 50 characters if you add one"},
			{"chars", true, "Letters, spaces, apostrophes, hyphens and periods"},
			{"letters", true, "At least one letter"},
		}
	}
	n, letters := 0, 0
	chars := true
	for _, r := range s {
		n++
		switch {
		case unicode.IsLetter(r):
			letters++
		case isNamePunct(r):
		default:
			chars = false
		}
	}
	return []RuleCheck{
		{"length", n >= 1 && n <= NameMax, "1 to 50 characters"},
		{"chars", chars && n > 0, "Letters, spaces, apostrophes, hyphens and periods"},
		{"letters", letters >= 1, "At least one letter"},
	}
}

func nameCode(field, suffix string) string {
	switch field {
	case "firstName":
		return "first_name_" + suffix
	case "middleName":
		return "middle_name_" + suffix
	default:
		return "last_name_" + suffix
	}
}

func nameLabel(field string) string {
	switch field {
	case "firstName":
		return "first name"
	case "middleName":
		return "middle name"
	default:
		return "last name"
	}
}

func nameFieldError(field, value string, required bool) *FieldError {
	value = strings.TrimSpace(value)
	if value == "" {
		if !required {
			return nil
		}
		return &FieldError{nameCode(field, "required"), "Enter your " + nameLabel(field) + ".", field}
	}
	switch firstFail(CheckName(value, true)) {
	case "length":
		return &FieldError{nameCode(field, "long"), "A " + nameLabel(field) + " can have at most 50 characters.", field}
	case "chars", "letters":
		return &FieldError{nameCode(field, "chars"), "Use letters, spaces, apostrophes, hyphens and periods in a " + nameLabel(field) + ", with at least one letter.", field}
	default:
		return nil
	}
}

// CheckEmailSyntax: a plain address (local@domain.tld), at most 254 characters.
func CheckEmailSyntax(e string) []RuleCheck {
	e = strings.TrimSpace(e)
	return []RuleCheck{{"syntax", e != "" && len(e) <= EmailMax && emailRe.MatchString(e), "A real email address, like name@example.com"}}
}

// AgeOn computes a whole-year age from a birth date. Age is never stored, only derived.
func AgeOn(birth, now time.Time) int {
	y := now.Year() - birth.Year()
	if now.Month() < birth.Month() || now.Month() == birth.Month() && now.Day() < birth.Day() {
		y--
	}
	return y
}

// ParseDOB parses MM/DD/YYYY strictly (a real calendar date).
func ParseDOB(s string) (time.Time, bool) {
	m := dobRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return time.Time{}, false
	}
	mo, _ := strconv.Atoi(m[1])
	d, _ := strconv.Atoi(m[2])
	y, _ := strconv.Atoi(m[3])
	t := time.Date(y, time.Month(mo), d, 0, 0, 0, 0, time.UTC)
	if t.Year() != y || int(t.Month()) != mo || t.Day() != d {
		return time.Time{}, false
	}
	return t, true
}

// CheckDOB validates a date of birth and returns the derived age (-1 when unknown).
func CheckDOB(s string, now time.Time, minAge int) ([]RuleCheck, int, *FieldError) {
	if minAge < CentralMinAge {
		minAge = CentralMinAge
	}
	fmtOK, rangeOK, minOK := false, false, false
	age := -1
	var fe *FieldError
	s = strings.TrimSpace(s)
	switch t, ok := ParseDOB(s); {
	case s == "":
		fe = &FieldError{"dob_required", "Enter your date of birth.", "dob"}
	case !dobRe.MatchString(s):
		fe = &FieldError{"dob_format", "Use MM/DD/YYYY, for example 07/04/2001.", "dob"}
	case !ok || t.After(now):
		fmtOK = true
		fe = &FieldError{"dob_invalid", "That date does not exist or is in the future.", "dob"}
	default:
		fmtOK = true
		age = AgeOn(t, now)
		rangeOK = age >= 0 && age <= MaxAge
		minOK = rangeOK && age >= minAge
		switch {
		case !rangeOK:
			fe = &FieldError{"dob_range", fmt.Sprintf("Age must be between 0 and %d.", MaxAge), "dob"}
		case !minOK:
			fe = &FieldError{"under_min_age", fmt.Sprintf("You must be at least %d to create a Red-XAI Account.", minAge), "dob"}
		}
	}
	return []RuleCheck{
		{"format", fmtOK, "MM/DD/YYYY, a real date, not in the future"},
		{"range", rangeOK, fmt.Sprintf("Age 0 to %d", MaxAge)},
		{"min_age", minOK, fmt.Sprintf("At least %d years old", minAge)},
	}, age, fe
}

func firstFail(checks []RuleCheck) string {
	for _, c := range checks {
		if !c.OK {
			return c.ID
		}
	}
	return ""
}

// SignupRequest is the body of POST /v1/signup in the Red-XAI Accounts contract (app is filled in by redxd).
type SignupRequest struct {
	App                  string `json:"app"`
	FirstName            string `json:"firstName"`
	MiddleName           string `json:"middleName,omitempty"`
	LastName             string `json:"lastName"`
	Username             string `json:"username"`
	Password             string `json:"password"`
	PasswordConfirm      string `json:"passwordConfirm"`
	Email                string `json:"email"`
	EmailConfirm         string `json:"emailConfirm"`
	DOB                  string `json:"dob"`
	TOSGrant             string `json:"tosGrant"`
	TwoFactor            string `json:"twoFactor"`
	Phone                string `json:"phone,omitempty"`
	AcceptNo2faRisk      bool   `json:"acceptNo2faRisk"`
	AcknowledgeFalseInfo bool   `json:"acknowledgeFalseInfo"`
}

// ValidateSignup applies every rule (the server-side mirror of the console's live hints).
func ValidateSignup(r *SignupRequest, now time.Time, minAge int) *FieldError {
	r.FirstName = strings.TrimSpace(r.FirstName)
	r.MiddleName = strings.TrimSpace(r.MiddleName)
	r.LastName = strings.TrimSpace(r.LastName)
	if fe := nameFieldError("firstName", r.FirstName, true); fe != nil {
		return fe
	}
	if fe := nameFieldError("middleName", r.MiddleName, false); fe != nil {
		return fe
	}
	if fe := nameFieldError("lastName", r.LastName, true); fe != nil {
		return fe
	}
	switch firstFail(CheckUsername(r.Username)) {
	case "length":
		if len([]rune(r.Username)) < UsernameMin {
			return &FieldError{"username_short", fmt.Sprintf("Usernames need at least %d characters.", UsernameMin), "username"}
		}
		return &FieldError{"username_long", fmt.Sprintf("Usernames can have at most %d characters.", UsernameMax), "username"}
	case "chars":
		return &FieldError{"username_chars", "Use only letters, numbers, _ . and - in a username.", "username"}
	case "letters":
		return &FieldError{"username_letters", fmt.Sprintf("Usernames need at least %d letters.", UsernameLetters), "username"}
	}
	switch firstFail(CheckPassword(r.Password)) {
	case "length":
		if len([]rune(r.Password)) < PasswordMin {
			return &FieldError{"password_short", fmt.Sprintf("Passwords need at least %d characters.", PasswordMin), "password"}
		}
		return &FieldError{"password_long", fmt.Sprintf("Passwords can have at most %d characters.", PasswordMax), "password"}
	case "upper":
		return &FieldError{"password_upper", "Add an upper-case letter.", "password"}
	case "lower":
		return &FieldError{"password_lower", "Add a lower-case letter.", "password"}
	case "digit":
		return &FieldError{"password_digit", "Add a number.", "password"}
	case "special":
		return &FieldError{"password_special", "Add a special character from " + SafeSpecials, "password"}
	case "chars":
		return &FieldError{"password_chars", "Use only letters, numbers and " + SafeSpecials, "password"}
	}
	if r.PasswordConfirm != r.Password {
		return &FieldError{"password_mismatch", "The two passwords are not the same.", "passwordConfirm"}
	}
	r.Email = strings.TrimSpace(r.Email)
	r.EmailConfirm = strings.TrimSpace(r.EmailConfirm)
	if r.Email == "" {
		return &FieldError{"email_required", "Enter your email address.", "email"}
	}
	if firstFail(CheckEmailSyntax(r.Email)) != "" {
		return &FieldError{"email_syntax", "That is not a valid email address.", "email"}
	}
	if !strings.EqualFold(r.EmailConfirm, r.Email) {
		return &FieldError{"email_mismatch", "The two email addresses are not the same.", "emailConfirm"}
	}
	if _, _, fe := CheckDOB(r.DOB, now, minAge); fe != nil {
		return fe
	}
	if strings.TrimSpace(r.TOSGrant) == "" {
		return &FieldError{"tos_required", "Read and agree to the Terms of Service first.", "tos"}
	}
	if !r.AcknowledgeFalseInfo {
		return &FieldError{"false_info_ack_required", "Confirm that you understand false information means the account cannot be recovered.", "acknowledgeFalseInfo"}
	}
	switch r.TwoFactor {
	case "app":
	case "phone":
		if !phoneRe.MatchString(strings.TrimSpace(r.Phone)) {
			return &FieldError{"phone_invalid", "Enter the phone number with its country code, like +15555550123.", "phone"}
		}
	case "none":
		if !r.AcceptNo2faRisk {
			return &FieldError{"no2fa_ack_required", "Confirm that you accept the risk of having no two-factor authentication.", "acceptNo2faRisk"}
		}
	case "redxai_auth":
		return &FieldError{"twofactor_unavailable", "Red-XAI Auth is coming soon. Choose Phone, App or None for now.", "twoFactor"}
	default:
		return &FieldError{"twofactor_invalid", "Choose a two-factor option.", "twoFactor"}
	}
	if r.TwoFactor != "phone" {
		r.Phone = ""
	}
	return nil
}
