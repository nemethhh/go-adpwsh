package adpwsh_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	adpwsh "github.com/nemethhh/go-adpwsh"
	"github.com/nemethhh/go-adpwsh/transport/fake"
)

func userData() map[string]any {
	return map[string]any{
		"objectGUID":            "cc33dd44-0000-0000-0000-000000000003",
		"distinguishedName":     "CN=jdoe,OU=Staff,DC=corp,DC=local",
		"name":                  "jdoe",
		"samAccountName":        "jdoe",
		"userPrincipalName":     "jdoe@corp.local",
		"displayName":           "John Doe",
		"givenName":             "John",
		"surname":               "Doe",
		"description":           "",
		"enabled":               true,
		"sid":                   "S-1-5-21-1-2-3-1104",
		"changePasswordAtLogon": false,
		"canChangePassword":     true,
		"passwordExpires":       true,
		"accountExpirationDate": nil,
	}
}

func TestUserCreateSendsPasswordSeparatelyFromTheSplat(t *testing.T) {
	var payload map[string]any
	tr := fake.New(func(c fake.Call) fake.Response {
		switch c.Op {
		case "rootdse":
			return fake.OK(rootDSE())
		case "user_create":
			payload = c.Payload
			return fake.OK(userData())
		}
		t.Fatalf("unexpected op %q", c.Op)
		return fake.Response{}
	})
	client := mustClient(t, adpwsh.Config{Transport: tr})

	pw := adpwsh.NewSecret("Correct-Horse-Battery-Staple-1")
	u, err := client.User.Create(context.Background(), adpwsh.UserSpec{
		SamAccountName:    "jdoe",
		Container:         "OU=Staff,DC=corp,DC=local",
		Name:              adpwsh.String("jdoe"),
		UserPrincipalName: adpwsh.String("jdoe@corp.local"),
		GivenName:         adpwsh.String("John"),
		Surname:           adpwsh.String("Doe"),
		DisplayName:       adpwsh.String("John Doe"),
		Enabled:           adpwsh.Bool(true),
		Password:          &pw,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// The password rides beside the splat so the script can turn it into a
	// SecureString; it is never a command-line argument.
	if payload["password"] != "Correct-Horse-Battery-Staple-1" {
		t.Errorf("password not delivered to the script")
	}
	create, _ := payload["create"].(map[string]any)
	if _, present := create["AccountPassword"]; present {
		t.Error("AccountPassword must not be in the splat; the script builds the SecureString")
	}
	if create["SamAccountName"] != "jdoe" || create["Path"] != "OU=Staff,DC=corp,DC=local" ||
		create["Surname"] != "Doe" || create["Enabled"] != true {
		t.Errorf("create splat = %v", create)
	}
	if u.SID == "" || u.Container != "OU=Staff,DC=corp,DC=local" || u.AccountExpiration != nil {
		t.Errorf("user = %+v", u)
	}
}

// The Name defaults to the sAMAccountName, which is what makes the common case
// a two-field spec.
func TestUserCreateDefaultsNameToSam(t *testing.T) {
	var create map[string]any
	tr := fake.New(func(c fake.Call) fake.Response {
		if c.Op == "rootdse" {
			return fake.OK(rootDSE())
		}
		create, _ = c.Payload["create"].(map[string]any)
		return fake.OK(userData())
	})
	client := mustClient(t, adpwsh.Config{Transport: tr})
	if _, err := client.User.Create(context.Background(), adpwsh.UserSpec{
		SamAccountName: "jdoe", Container: "OU=Staff,DC=corp,DC=local",
	}); err != nil {
		t.Fatal(err)
	}
	if create["Name"] != "jdoe" {
		t.Errorf("Name = %v, want the sAMAccountName", create["Name"])
	}
}

// The tier-1 booleans are cmdlet parameters, and two of them are inverted.
// The provider surface is positive; the inversion happens once, here.
func TestUserCreateInvertsTheNegativeFlags(t *testing.T) {
	var create map[string]any
	tr := fake.New(func(c fake.Call) fake.Response {
		if c.Op == "rootdse" {
			return fake.OK(rootDSE())
		}
		create, _ = c.Payload["create"].(map[string]any)
		return fake.OK(userData())
	})
	client := mustClient(t, adpwsh.Config{Transport: tr})
	if _, err := client.User.Create(context.Background(), adpwsh.UserSpec{
		SamAccountName: "jdoe", Container: "OU=Staff,DC=corp,DC=local",
		CanChangePassword: adpwsh.Bool(false),
		PasswordExpires:   adpwsh.Bool(false),
	}); err != nil {
		t.Fatal(err)
	}
	if create["CannotChangePassword"] != true {
		t.Errorf("can_change_password=false must send -CannotChangePassword $true: %v", create)
	}
	if create["PasswordNeverExpires"] != true {
		t.Errorf("password_expires=false must send -PasswordNeverExpires $true: %v", create)
	}
}

// Correctness rule 7: AD accepts incoherent combinations and behaves
// unexpectedly later, so they are rejected before a round trip.
func TestUserRejectsContradictoryFlags(t *testing.T) {
	tr := fake.New(func(fake.Call) fake.Response { return fake.OK(rootDSE()) })
	client := mustClient(t, adpwsh.Config{Transport: tr})
	tests := []struct {
		name string
		spec adpwsh.UserSpec
		want string
	}{
		{"must change but password never expires",
			adpwsh.UserSpec{SamAccountName: "jdoe", Container: "OU=Staff,DC=corp,DC=local",
				ChangePasswordAtLogon: adpwsh.Bool(true), PasswordExpires: adpwsh.Bool(false)},
			"password_expires"},
		{"must change but cannot change",
			adpwsh.UserSpec{SamAccountName: "jdoe", Container: "OU=Staff,DC=corp,DC=local",
				ChangePasswordAtLogon: adpwsh.Bool(true), CanChangePassword: adpwsh.Bool(false)},
			"can_change_password"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.User.Create(context.Background(), tt.spec)
			if !errors.Is(err, adpwsh.ErrConstraint) {
				t.Fatalf("want KindConstraint, got %v", err)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q should name %q", err, tt.want)
			}
		})
	}
}

// Surname's LDAP name is sn. Clearing it through "surname" would silently do
// nothing, which is exactly the class of bug -Clear invites.
func TestUserUpdateClearsSurnameThroughSn(t *testing.T) {
	var set map[string]any
	tr := fake.New(func(c fake.Call) fake.Response {
		switch c.Op {
		case "rootdse":
			return fake.OK(rootDSE())
		case "user_read":
			return fake.OK(userData())
		case "user_update":
			set, _ = c.Payload["set"].(map[string]any)
			return fake.OK(userData())
		}
		return fake.Response{}
	})
	client := mustClient(t, adpwsh.Config{Transport: tr})
	if _, err := client.User.Update(context.Background(), adpwsh.ByGUID("cc33"), adpwsh.UserSpec{
		SamAccountName: "jdoe", Container: "OU=Staff,DC=corp,DC=local",
		Name: adpwsh.String("jdoe"), Surname: adpwsh.String(""), Description: adpwsh.String(""),
	}); err != nil {
		t.Fatal(err)
	}
	clear, _ := set["Clear"].([]any)
	got := map[string]bool{}
	for _, v := range clear {
		got[v.(string)] = true
	}
	if !got["sn"] || !got["description"] {
		t.Errorf("Clear = %v, want sn and description", clear)
	}
	if got["surname"] {
		t.Error("surname is not an LDAP attribute name; sn is")
	}
}

// OptTime is the three-state carrier a pointer cannot express, because
// time.Time has no empty sentinel. "Never expires" is Set-ADUser
// -AccountExpirationDate $null, NOT -Clear accountExpires: accountExpires is a
// system attribute that is always present (its "never" value is
// 0x7FFFFFFFFFFFFFFF), and AD refuses to remove it with
// ADIllegalModifyOperationException.
func TestUserAccountExpiration(t *testing.T) {
	when := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
	tests := []struct {
		name      string
		opt       adpwsh.OptTime
		wantKey   bool // AccountExpirationDate present in the Set-ADUser splat
		wantParam any  // its value when present ($null marshals from a Go nil)
	}{
		{"leave alone", adpwsh.OptTime{}, false, nil},
		{"set", adpwsh.SetTime(when), true, "2027-01-02T03:04:05Z"},
		{"clear means never expires", adpwsh.ClearTime(), true, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var set map[string]any
			tr := fake.New(func(c fake.Call) fake.Response {
				switch c.Op {
				case "rootdse":
					return fake.OK(rootDSE())
				case "user_read":
					return fake.OK(userData())
				default:
					set, _ = c.Payload["set"].(map[string]any)
					return fake.OK(userData())
				}
			})
			client := mustClient(t, adpwsh.Config{Transport: tr})
			if _, err := client.User.Update(context.Background(), adpwsh.ByGUID("cc33"), adpwsh.UserSpec{
				SamAccountName: "jdoe", Container: "OU=Staff,DC=corp,DC=local",
				Name: adpwsh.String("jdoe"), AccountExpiration: tt.opt,
			}); err != nil {
				t.Fatal(err)
			}
			got, ok := set["AccountExpirationDate"]
			if ok != tt.wantKey {
				t.Errorf("AccountExpirationDate present = %v, want %v (set=%v)", ok, tt.wantKey, set)
			}
			if tt.wantKey && got != tt.wantParam {
				t.Errorf("AccountExpirationDate = %v, want %v", got, tt.wantParam)
			}
			// -Clear accountExpires is the illegal modify a real DC rejects; it
			// must never appear, whatever the OptTime state.
			clear, _ := set["Clear"].([]any)
			for _, v := range clear {
				if v == "accountExpires" {
					t.Error("accountExpires must not be cleared via -Clear; use -AccountExpirationDate $null")
				}
			}
		})
	}
}

// Rotation goes through Set-ADAccountPassword -Reset; -AccountPassword does
// not exist on Set-ADUser.
func TestUserSetPassword(t *testing.T) {
	var op string
	var sent any
	tr := fake.New(func(c fake.Call) fake.Response {
		if c.Op == "rootdse" {
			return fake.OK(rootDSE())
		}
		op, sent = c.Op, c.Payload["password"]
		if !strings.Contains(c.Script, "Set-ADAccountPassword") || !strings.Contains(c.Script, "-Reset") {
			t.Errorf("wrong cmdlet:\n%s", c.Script)
		}
		return fake.OK(map[string]any{"reset": true})
	})
	client := mustClient(t, adpwsh.Config{Transport: tr})
	if err := client.User.SetPassword(context.Background(), adpwsh.ByGUID("cc33"), adpwsh.NewSecret("New-P4ssw0rd!")); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if op != "user_setpassword" || sent != "New-P4ssw0rd!" {
		t.Errorf("op = %q, password delivered = %v", op, sent != nil)
	}
}

// A password-policy failure must never echo the password back.
func TestUserSetPasswordErrorDoesNotEchoTheSecret(t *testing.T) {
	tr := fake.New(func(c fake.Call) fake.Response {
		if c.Op == "rootdse" {
			return fake.OK(rootDSE())
		}
		return fake.Fail("Microsoft.ActiveDirectory.Management.ADPasswordComplexityException",
			"The password does not meet the length, complexity, or history requirement", 0x052D)
	})
	client := mustClient(t, adpwsh.Config{Transport: tr})
	err := client.User.SetPassword(context.Background(), adpwsh.ByGUID("cc33"), adpwsh.NewSecret("weak"))
	if !errors.Is(err, adpwsh.ErrPassword) {
		t.Fatalf("want KindPassword, got %v", err)
	}
	if strings.Contains(err.Error(), "weak") {
		t.Errorf("the error echoed the password: %v", err)
	}
}

// Hostile input is data, never script text. This is the offline half of the
// injection suite; the acceptance suite runs the same table against real AD.
func TestUserHostileInputIsJustData(t *testing.T) {
	hostile := []string{
		`under_score`, `has "quotes"`, `has 'single'`, `$var`, "back`tick",
		`semi;colon`, `amper&sand`, `pipe|char`, `Smith, John`, `söüäß-éòñ`,
	}
	for _, h := range hostile {
		t.Run(h, func(t *testing.T) {
			var create map[string]any
			tr := fake.New(func(c fake.Call) fake.Response {
				if c.Op == "rootdse" {
					return fake.OK(rootDSE())
				}
				create, _ = c.Payload["create"].(map[string]any)
				// The script is constant: hostile input cannot appear in it.
				if strings.Contains(c.Script, h) {
					t.Errorf("value %q reached the script text", h)
				}
				return fake.OK(userData())
			})
			client := mustClient(t, adpwsh.Config{Transport: tr})
			if _, err := client.User.Create(context.Background(), adpwsh.UserSpec{
				SamAccountName: "jdoe", Container: "OU=Staff,DC=corp,DC=local",
				DisplayName: adpwsh.String(h),
			}); err != nil {
				t.Fatal(err)
			}
			if create["DisplayName"] != h {
				t.Errorf("value was altered in transit: %q became %v", h, create["DisplayName"])
			}
		})
	}
}
