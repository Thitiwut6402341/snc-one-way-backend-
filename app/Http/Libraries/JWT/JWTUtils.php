<?php

namespace App\Http\Libraries\JWT;

use App\Http\Libraries\JWT\JWT;
use App\Http\Libraries\JWT\Key;

// define("PRIVATE_KEY", "<Secret Key>");
define("PRIVATE_KEY", "-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBAMC6eSB5Z6rNzJHneNMwZWLJKWOZ2ljKIP96OYNJ64OzRIRXxLQ/
SunI9HH1rbyRbCh8tsWeq9ZfO3hLR3LY7qMCAwEAAQJAF5f8chxKs59EFuyGXxxC
nShRN89C6rG7/mqhFdB704BtTw50ntuy8eH6c2aCrjVkP0osuAVY3GIMSHeHkaej
eQIhAOTg0CQSvrIKcEOadTZBaM7n0HQjVnmtr92NM9dCGsP/AiEA15EH0DIyNHBG
tz5HkltYA/GPEF9FxlFOobT7Kpe0RV0CIQCiB/XSU+LksDch5Ost6ciFEd+lGI9T
vP5P3nLg5U+FiQIgCwQBRzVZdW6LXo/TLnp2e/UbH3YO5bx/7SmHcDzCXI0CIQCM
k1QtQFaT7t1H+ZHfq5ygMDJCJWuJ+YGbAYl6LtsoAw==
-----END RSA PRIVATE KEY-----");

class JWTUtils
{
     public function generateToken($payload)
     {
          $token = JWT::encode($payload, PRIVATE_KEY, 'HS256');
          return $token;
     }

     public function verifyToken($header)
     {
          $token = null;
          // extract the token from the header
          if (!empty($header)) {
               if (preg_match('/Bearer\s(\S+)/', $header, $matches)) {
                    $token = $matches[1];
               }
          }

          // check if token is null or empty
          if (is_null($token) || empty($token)) {
               return (object)['state' => false, 'msg' => 'Access denied', 'decoded' => []];
          }

          try {
               $decoded = JWT::decode($token, new Key(PRIVATE_KEY, 'HS256'));
               return (object)['state' => true, 'msg' => 'OK', 'decoded' => $decoded];
          } catch (\Exception $e) {
               return (object)['state' => false, 'msg' => $e->getMessage(), 'decoded' => []];
          }
     }
}
