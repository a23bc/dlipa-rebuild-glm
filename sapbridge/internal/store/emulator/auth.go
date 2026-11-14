package emulator

import (
	"errors"
)

func (r *Runtime) newCredentialTask(account, bag uint64, password string, source uint64) (uint64, error) {
	if r.ClassAddress("AMSVerifyCredentialsTask") == 0 {
		return 0, errors.New("authentication plugin is missing from the profile")
	}

	options, err := r.Invoke(r.New("AMSAuthenticateOptions", nil), "init")
	if err != nil {
		return 0, err
	}

	r.registerGuestObject(options, "AMSAuthenticateOptions")

	fields := map[string]uint64{"setEphemeral:": 1, "setCanMakeAccountActive:": 0, "setAllowServerDialogs:": 0, "setPassword:": r.New("NSString", password), "setCredentialSource:": source}
	for selector, value := range fields {
		if _, err = r.Invoke(options, selector, value); err != nil {
			return 0, err
		}
	}
	// These entry points consume account/options/bag; the full task initializer
	// additionally starts analytics and account persistence services. Keep the
	// request boundary independent of host analytics and account persistence.
	task, err := r.Invoke(r.New("AMSVerifyCredentialsTask", nil), "init")
	if err != nil {
		return 0, err
	}

	// init can answer with a different object than the receiver; the SetIvar
	// calls below need it in the host's table (584-2).
	r.registerGuestObject(task, "AMSVerifyCredentialsTask")

	for name, value := range map[string]uint64{"_account": account, "_options": options, "_bag": bag} {
		if err = r.SetIvar(task, name, value); err != nil {
			return 0, err
		}
	}

	return task, nil
}
