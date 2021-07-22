#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

///! From `login_getclass(3)`:
///!
///! ```no_build
///! HISTORY
///!     The login_getclass function first appeared in OpenBSD 2.8.
///! 
///! CAVEATS
///!     The string returned by login_getcapstr() is allocated via malloc(3) when
///!     the specified capability is present and thus it is the responsibility of
///!     the caller to free() this space.  However, if the capability was not
///!     found or an error occurred and def or err (whichever is relevant) are
///!     non-NULL the returned value is simply what was passed in to
///!     login_getcapstr().  Therefore it is not possible to blindly free() the
///!     return value without first checking it against def and err.
///!
///!	 The same warnings set forth in setlogin(2) apply to setusercontext() when
///!     the LOGIN_SETLOGIN flag is used.  Specifically, changing the login name
///!     affects all processes in the current session, not just the current
///!     process.  See setlogin(2) for more information.

use std::os::raw::{c_char, c_int, c_uint};

/// Set the group ID and call initgroups(3).
/// Requires the pwd field be specified.
pub const LOGIN_SETGROUP: c_uint = 0x0001;

/// Set the login name set by setlogin(2).
/// Requires the pwd field be specified.
pub const LOGIN_SETLOGIN: c_uint = 0x0002;

/// Sets the PATH environment variable.
pub const LOGIN_SETPATH: c_uint = 0x0004;

/// Swets the priority by setpriority(2).
pub const LOGIN_SETPRIORITY: c_uint = 0x0008;

/// Sets the various system resources by setrlimit(2).
pub const LOGIN_SETRESOURCES: c_uint = 0x0010;

/// Sets the umask by umask(2).
pub const LOGIN_SETUMASK: c_uint = 0x0020;

/// Sets the user ID to uid by setuid(2).
pub const LOGIN_SETUSER: c_uint = 0x0040;

/// Sets environment variables specified by the setenv keyword.
pub const LOGIN_SETENV: c_uint = 0x0080;

/// Sets all of the above.
pub const LOGIN_SETALL: c_uint = 0x00ff;

/// Accepted authentication
pub const BI_AUTH: &'static [u8; 9] = b"authorize";

/// Rejected authentication
pub const BI_REJECT: &'static [u8; 6] = b"reject";

/// Reject with a challenge
pub const BI_CHALLENGE: &'static [u8; 16] = b"reject challenge";

/// Reject silently
pub const BI_SILENT: &'static [u8; 13] = b"reject silent";

/// Remove file on error
pub const BI_REMOVE: &'static [u8; 6] = b"remove";

/// Root authenticated
pub const BI_ROOTOKAY: &'static [u8; 14] = b"authorize root";

/// Ok on non-secure line
pub const BI_SECURE: &'static [u8; 16] = b"authorize secure";

/// Set environment variable
pub const BI_SETENV: &'static [u8; 6] = b"setenv";

/// Unset environment variable
pub const BI_UNSETENV: &'static [u8; 8] = b"unsetenv";

/// Set local variable
pub const BI_VALUE: &'static [u8; 5] = b"value";

/// Account expired
pub const BI_EXPIRED: &'static [u8; 14] = b"reject expired";

/// Password expired
pub const BI_PWEXPIRED: &'static [u8; 16] = b"reject pwexpired";

/// Child is passing an fd
pub const BI_FDPASS: &'static [u8; 2] = b"fd";

// Bits which can be returned by authenticate()/auth_scan()

/// User authenticated
pub const AUTH_OKAY: c_uint = 0x01;

/// Authenticated as root
pub const AUTH_ROOTOKAY: c_uint = 0x02;

/// Secure login
pub const AUTH_SECURE: c_uint = 0x04;

/// Silent rejection
pub const AUTH_SILENT: c_uint = 0x08;

/// A challenge was given
pub const AUTH_CHALLENGE: c_uint = 0x10;

/// Account expired
pub const AUTH_EXPIRED: c_uint = 0x20;

/// Password expired
pub const AUTH_PWEXPIRED: c_uint = 0x40;

/// Bitwise OR (AUTH_OKAY | AUTH_ROOTOKAY | AUTH_SECURE)
pub const AUTH_ALLOW: c_uint = AUTH_OKAY | AUTH_ROOTOKAY | AUTH_SECURE;

/// Raw type for login capability, aliased as `login_cap_t`
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct login_cap {
    pub lc_class: *mut c_char,
    pub lc_cap: *mut c_char,
    pub lc_style: *mut c_char,
}

/// Alias for the login capability type `login_cap`
pub type login_cap_t = login_cap;

pub type quad_t = i64;

extern "C" {
	/// From `login_getclass(3)`:
	///
	/// ```no_build
	/// The login_getclass() function extracts the entry specified by class (or
    /// default if class is NULL or the empty string) from /etc/login.conf (see
    /// login.conf(5)).  If the entry is found, a login_cap_t pointer is
    /// returned.  NULL is returned if the user class is not found.  When the
    /// login_cap_t structure is no longer needed, it should be freed by the
    /// login_close() function.
	/// ```
    pub fn login_getclass(_class: *mut c_char) -> *mut login_cap_t;

	/// From `login_getclass(3)`:
	///
	/// ```no_build
	/// The login_getstyle() function is used to obtain
    /// the style of authentication that should be used for this user class.  The
    /// style argument may either be NULL or the desired style of authentication.
    /// If NULL, the first available authentication style will be used.  The type
    /// argument refers to the type of authentication being performed.  This is
    /// used to override the standard auth entry in the database.  By convention
    /// this should be of the form "auth-type".  Future releases may remove the
    /// requirement for the "auth-" prefix and add it if it is missing.  If type
    /// is NULL then only "auth" will be looked at (see login.conf(5)).  The
    /// login_getstyle() function will return NULL if the desired style of
    /// authentication is not available, or if no style is available.
	/// ```
    pub fn login_getstyle(_lc: *mut login_cap_t, _style: *mut c_char, _type: *mut c_char) -> *mut c_char;

	/// From `login_getclass(3)`:
	///
	/// ```no_build
    /// The login_getcapbool() function returns def if no capabilities were found for
	/// this class (typically meaning that the default class was used and the /etc/login.conf file is missing).
	/// It returns a non-zero value if cap, with no value, was found, zero otherwise.
	/// ```
    pub fn login_getcapbool(_lc: *mut login_cap_t, _cap: *mut c_char, _def: c_uint) -> c_int;

	/// From `login_getclass(3)`:
	///
	/// ```no_build
	/// The login_getcapnum() function queries the database entry for a field
    /// named cap.  If the field is found, its value is returned.  If the field
    /// is not found, the value specified by def is returned.  If an error is
    /// encountered while trying to find the field, err is returned.  See
    /// login.conf(5) for a discussion of the various textual forms the value may
    /// take.
	/// ```
    pub fn login_getcapnum(_lc: *mut login_cap_t, _cap: *mut c_char, _def: quad_t, _err: quad_t) -> quad_t;

	/// From `login_getclass(3)`:
	///
	/// ```no_build
	/// The login_getcapsize() function queries the database entry for a field
    /// named cap.  If the field is found, its value is returned.  If the field
    /// is not found, the value specified by def is returned.  If an error is
    /// encountered while trying to find the field, err is returned.  See
    /// login.conf(5) for a discussion of the various textual forms the value may
    /// take.
	/// ```
    pub fn login_getcapsize(_lc: *mut login_cap_t, _cap: *mut c_char, _def: quad_t, _err: quad_t) -> quad_t;

	/// From `login_getclass(3)`:
	///
	/// ```no_build
	/// The login_getcapstr() function queries the database entry for a field
    /// named cap.  If the field is found, its value is returned.  If the field
    /// is not found, the value specified by def is returned.  If an error is
    /// encountered while trying to find the field, err is returned.  See
    /// login.conf(5) for a discussion of the various textual forms the value may
    /// take.
	/// ```
    pub fn login_getcapstr(_lc: *mut login_cap_t, _cap: *mut c_char, _def: *mut c_char, _err: *mut c_char) -> *mut c_char;

	/// From `login_getclass(3)`:
	///
	/// ```no_build
	/// The login_getcaptime() function queries the database entry for a field
    /// named cap.  If the field is found, its value is returned.  If the field
    /// is not found, the value specified by def is returned.  If an error is
    /// encountered while trying to find the field, err is returned.  See
    /// login.conf(5) for a discussion of the various textual forms the value may
    /// take.
	/// ```
    pub fn login_getcaptime(_lc: *mut login_cap_t, _cap: *mut c_char, _def: quad_t, _err: quad_t) -> quad_t;

	/// From `login_getclass(3)`:
	///
	/// ```no_build
    /// When the login_cap_t structure is no longer needed, it should be freed by the
    /// login_close() function.
	/// ```
    pub fn login_close(_lc: *mut login_cap_t);

	/// From `login_getclass(3)`:
	///
	/// ```no_build
    /// The secure_path() function takes a path name and returns 0 if the path
    /// name is secure, -1 if not.  To be secure a path must exist, be a regular
    /// file (and not a directory), owned by root, and only writable by the owner
    /// (root).
 	/// ```
    pub fn secure_path(_path: *mut c_char) -> c_int;

	/// From `login_getclass(3)`:
    ///
	/// ```no_build
    /// The setclasscontext() function takes class, the name of a user class, and
    /// sets the resources defined by that class according to flags.  Only the
    /// LOGIN_SETPATH, LOGIN_SETPRIORITY, LOGIN_SETRESOURCES, and LOGIN_SETUMASK
    /// bits are used (see setusercontext() below).  It returns 0 on success and
    /// -1 on failure.
	/// ```
    pub fn setclasscontext(_class: *mut c_char, _flags: c_uint) -> c_int;

    /// From `login_getclass(3)`:
    ///
    /// ```no_build
    /// The setusercontext() function sets the resources according to flags.  The
    /// lc argument, if not NULL, contains the class information that should be
    /// used. The pwd argument, if not NULL, provides information about the
    /// user. Both lc and pwd cannot be NULL.  The uid argument is used in place
    /// of the user ID contained in the pwd structure when calling setuid(2).
    /// The setusercontext() function returns 0 on success and -1 on failure.
    /// The various bits available to be or-ed together to make up flags are:
    ///
    /// LOGIN_SETENV          Sets environment variables specified by the setenv
	///						  keyword.
    /// LOGIN_SETGROUP        Set the group ID and call initgroups(3).  Requires
    ///                       the pwd field be specified.
    ///
    /// LOGIN_SETLOGIN        Sets the login name by setlogin(2).  Requires the
    ///                       pwd field be specified.
    ///
    /// LOGIN_SETPATH         Sets the PATH environment variable.
    ///
    /// LOGIN_SETPRIORITY     Sets the priority by setpriority(2).
    ///
    /// LOGIN_SETRESOURCES    Sets the various system resources by setrlimit(2).
    ///
    /// LOGIN_SETUMASK        Sets the umask by umask(2).
    ///
    /// LOGIN_SETUSER         Sets the user ID to uid by setuid(2).
    ///
    /// LOGIN_SETALL          Sets all of the above.
    /// ```
    pub fn setusercontext(_lc: *mut login_cap_t, _pwd: *mut libc::passwd, _uid: libc::uid_t, _flags: c_uint) -> c_int;
}
