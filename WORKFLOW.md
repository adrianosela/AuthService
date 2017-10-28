## Auth Workflow with JWTs Demo:

#### Spinning up Auth Server:

```
15:59 $ make up
go get -v
go vet -x
/usr/local/go/pkg/tool/darwin_amd64/vet main.go
go build -ldflags "-X main.buildVersion=0.1-982cdad" -o AuthService
./AuthService
2017/10/22 16:00:20 [DEBUG] user: adriano, password: 07769cc3-c12b-405b-84ba-e480f1ff54fe
2017/10/22 16:00:20 [DEBUG] user: miguel, password: edacde8e-3cd6-429f-b85e-2329123c8769
2017/10/22 16:00:20 [DEBUG] user: felipe, password: 1a54934e-cd10-49fc-aba6-f71f3369bdf2
2017/10/22 16:00:20 [DEBUG] user: adrian, password: 9ff3a502-f192-4fac-b9a6-00443d657302
2017/10/22 16:00:20 [DEBUG] user: antonio, password: ae8aa63b-8d80-40be-b6d8-a465c6b12f52
2017/10/22 16:00:20 [MOCK_DB] Added New User: {"uname":"adriano","id":"26776181-dfe3-4902-a38b-1120ef5e72b0"}
2017/10/22 16:00:20 [MOCK_DB] Added New User: {"uname":"miguel","id":"e11455cd-8be3-45b6-9c84-c01c2efef7e8"}
2017/10/22 16:00:20 [MOCK_DB] Added New User: {"uname":"felipe","id":"62820999-025f-48d2-a78a-0455f1355d03"}
2017/10/22 16:00:20 [MOCK_DB] Added New User: {"uname":"adrian","id":"bfcb8c67-2afa-4bb1-b1cc-9b8cee38fcfc"}
2017/10/22 16:00:20 [MOCK_DB] Added New User: {"uname":"antonio","id":"7490db07-8919-46cc-b01e-3ee4d2d643b5"}
2017/10/22 16:00:20 [MOCK_DB] Added New Group: {"name":"Everyone","id":"06620084-df29-4349-88bb-4198c05b415b"}
2017/10/22 16:00:20 [MOCK_DB] Added New Group: {"name":"Developers","id":"d515c027-be4b-4ac1-9791-e89fbb71cccf"}
2017/10/22 16:00:20 [MOCK_DB] Added New Group: {"name":"Infrastructure","id":"a23f767e-9260-48d3-9d8d-68c4e35b6f73"}
2017/10/22 16:00:20 [MOCK_DB] Added New Group: {"name":"GameServer","id":"ee413571-9282-42f2-8417-f8b87861e490"}
2017/10/22 16:00:21 [INFO] Generated New Key-Pair: {"id":"bb13fa74-d83e-45ce-a5dd-cf47b9d3e326"}
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxvB3Jwyw2Vz9+ilEOZR7
C4kFHOHDapg+kzFDnZT3fYU9tItNsJ9gnTDA0LuArWkBJy++UnsOeO5Q6JngSmjL
jfN8HSYC0X6STCFSCYLah2OAQ6oVQ/vHkjUOdg31AQ+/Bld43PEHzb+/6ao+GNuu
LBfwFsaUf0noWGTCDFLaJKNBqgHEIfXvvEbtwzG8kktM9k2OhxMOSIL4PyDGaZgY
GTi0kZXTb1GNug954/mdU+6Acy9Ri4pq12OwppODbIQl8ysmXco4XCzDwDYe9YM4
ZpXfu19+8n40iYWG9MLB/gAIIXnra+Cux9HpVMcFKCrkqojme1o08pjE/gv+g+4M
UwIDAQAB
-----END PUBLIC KEY-----
2017/10/22 16:00:21 [KEYS] Added New Key: {"id":"bb13fa74-d83e-45ce-a5dd-cf47b9d3e326"}
2017/10/22 16:00:21 [INFO] Listening on http://localhost:8080
```
* Take note of the GameServer users Group ID in the logs above: {"id":"ee413571-9282-42f2-8417-f8b87861e490"}. Note: To reproduce without looking at the auth logs --> hit the GET /groups endpoint
* Take note of which users are part of this group. We see this by hitting the AuthService's /groups endpoint:

```
16:12 $ http http://localhost:8080/groups/ee413571-9282-42f2-8417-f8b87861e490 | jq -r .
{
  "name": "GameServer",
  "id": "ee413571-9282-42f2-8417-f8b87861e490",
  "members": [
    "26776181-dfe3-4902-a38b-1120ef5e72b0",  
    "e11455cd-8be3-45b6-9c84-c01c2efef7e8",
    "bfcb8c67-2afa-4bb1-b1cc-9b8cee38fcfc"
  ],
  "owners": [
    "26776181-dfe3-4902-a38b-1120ef5e72b0"
  ]
}
```
* See that only "adriano", "miguel", and "adrian" are part of the group of authorized users, "felipe" and "antonio" are not 
* In this demo we will attempt to authenticate against another service which federates identity to our AuthService
* We will see how tokens reflect group membership and how clients can verify the tokens' validity.

#### Sample Service Federating Identity to my Auth Service:
In this example I have used my [Game Server](https://github.com/adrianosela/GameServer) as a client service of my Identity Provider. The Authentication workflow in this particular case is as follows:

* Client requests the available rooms:

```
16:00 $ http http://localhost:8081/rooms | jq -r .
{
  "rooms": [
    {
      "room_id": "564961a1-001d-46c0-806e-77a7e68ce461",
      "players": 2
    },
    {
      "room_id": "bbd6f18c-6ed8-4523-a82c-67ff2ddeb80a",
      "players": 2
    },
    {
      "room_id": "9acffa17-ad8a-4e02-8497-aa6bf982942f",
      "players": 2
    },
    {
      "room_id": "f322a369-c6cf-4571-866d-a4d6b353df29",
      "players": 2
    },
    {
      "room_id": "ebb3e49d-2435-4304-9c7e-c9b1635a95f2",
      "players": 2
    }
  ]
}
```

**Success Case:** (user is in authorized group)

* User presents BasicAuth credentials (username:password) to get a token from the AuthService:

```
16:12 $ http --auth=adriano:07769cc3-c12b-405b-84ba-e480f1ff54fe http://localhost:8080/auth/login | jq -r .
{
  "token": "eyJhbGciOiJSUzUxMiIsInNpZ19raWQiOiJiYjEzZmE3NC1kODNlLTQ1Y2UtYTVkZC1jZjQ3YjlkM2UzMjYiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJhZHJpYW5vc2VsYS9hbGwiLCJleHAiOjE1MDg3MTgxODksImp0aSI6IjYzZmNhNjViLTExMGEtNDFhNy04ZGE2LTZiMTFkNWUyMTExYiIsImlhdCI6MTUwODcxNDU4OSwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwibmJmIjoxNTA4NzE0NTg5LCJzdWIiOiIyNjc3NjE4MS1kZmUzLTQ5MDItYTM4Yi0xMTIwZWY1ZTcyYjAiLCJncnBzIjpbImQ1MTVjMDI3LWJlNGItNGFjMS05NzkxLWU4OWZiYjcxY2NjZiIsImEyM2Y3NjdlLTkyNjAtNDhkMy05ZDhkLTY4YzRlMzViNmY3MyIsImVlNDEzNTcxLTkyODItNDJmMi04NDE3LWY4Yjg3ODYxZTQ5MCIsIjA2NjIwMDg0LWRmMjktNDM0OS04OGJiLTQxOThjMDViNDE1YiJdfQ.vuQrMiYsRefLX964R0D8ccWe_mRfQCcE9VFoedodgFQkMzP9WsCj5xsPSRtkdoooaf5hZYQYpaOvQRPJPMVpAZNHpLw-v6Dp4a5oBgWaOBIjn7lqO7j-aCtqYiCrS4sY25rJ5AZploObKCYLQS0e-Ib3gYMMDz33I7by0Yp0nBfJgOAALYLHUqm7acIFVQxisVXGbwnRoR4iaaRLTRQeFLtLA2MVpMgT985j2hq8XCHgSekFBQnyt2FiR1Xh4jVS5NYVKLNc0OFoK5FLUPl0WOanSmbQD-JzdilZiSdKRYUaTyuV21kjB_HVWyZUuyfOMUP99LtGnRs-1qTcfKFVxw",
  "valid_until": 1508718189
}
```

* User then presents his/her token to the appropriate endpoint on the GameServer:

```
16:25 $ http POST http://localhost:8081/join/564961a1-001d-46c0-806e-77a7e68ce461 'Authorization:eyJhbGciOiJSUzUxMiIsInNpZ19raWQiOiJiYjEzZmE3NC1kODNlLTQ1Y2UtYTVkZC1jZjQ3YjlkM2UzMjYiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJhZHJpYW5vc2VsYS9hbGwiLCJleHAiOjE1MDg3MTgxODksImp0aSI6IjYzZmNhNjViLTExMGEtNDFhNy04ZGE2LTZiMTFkNWUyMTExYiIsImlhdCI6MTUwODcxNDU4OSwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwibmJmIjoxNTA4NzE0NTg5LCJzdWIiOiIyNjc3NjE4MS1kZmUzLTQ5MDItYTM4Yi0xMTIwZWY1ZTcyYjAiLCJncnBzIjpbImQ1MTVjMDI3LWJlNGItNGFjMS05NzkxLWU4OWZiYjcxY2NjZiIsImEyM2Y3NjdlLTkyNjAtNDhkMy05ZDhkLTY4YzRlMzViNmY3MyIsImVlNDEzNTcxLTkyODItNDJmMi04NDE3LWY4Yjg3ODYxZTQ5MCIsIjA2NjIwMDg0LWRmMjktNDM0OS04OGJiLTQxOThjMDViNDE1YiJdfQ.vuQrMiYsRefLX964R0D8ccWe_mRfQCcE9VFoedodgFQkMzP9WsCj5xsPSRtkdoooaf5hZYQYpaOvQRPJPMVpAZNHpLw-v6Dp4a5oBgWaOBIjn7lqO7j-aCtqYiCrS4sY25rJ5AZploObKCYLQS0e-Ib3gYMMDz33I7by0Yp0nBfJgOAALYLHUqm7acIFVQxisVXGbwnRoR4iaaRLTRQeFLtLA2MVpMgT985j2hq8XCHgSekFBQnyt2FiR1Xh4jVS5NYVKLNc0OFoK5FLUPl0WOanSmbQD-JzdilZiSdKRYUaTyuV21kjB_HVWyZUuyfOMUP99LtGnRs-1qTcfKFVxw'
HTTP/1.1 200 OK
Content-Length: 11
Content-Type: text/plain; charset=utf-8
Date: Sun, 22 Oct 2017 23:26:13 GMT

joined room

```

**Failure Case:** (user is not in authorized group)


* User presents BasicAuth credentials (username:password) to get a token from the AuthService:

```
16:30 $ http --auth=felipe:1a54934e-cd10-49fc-aba6-f71f3369bdf2 http://localhost:8080/auth/login | jq -r .
{
  "token": "eyJhbGciOiJSUzUxMiIsInNpZ19raWQiOiJiYjEzZmE3NC1kODNlLTQ1Y2UtYTVkZC1jZjQ3YjlkM2UzMjYiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJhZHJpYW5vc2VsYS9hbGwiLCJleHAiOjE1MDg3MTg2NTIsImp0aSI6IjhhZTU2YjUxLWRjMWYtNGY3Ny05ZDVkLTgwM2QyMTZlMDk2ZSIsImlhdCI6MTUwODcxNTA1MiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwibmJmIjoxNTA4NzE1MDUyLCJzdWIiOiI2MjgyMDk5OS0wMjVmLTQ4ZDItYTc4YS0wNDU1ZjEzNTVkMDMiLCJncnBzIjpbIjA2NjIwMDg0LWRmMjktNDM0OS04OGJiLTQxOThjMDViNDE1YiIsImQ1MTVjMDI3LWJlNGItNGFjMS05NzkxLWU4OWZiYjcxY2NjZiIsImEyM2Y3NjdlLTkyNjAtNDhkMy05ZDhkLTY4YzRlMzViNmY3MyJdfQ.Gch13sVDrng0eseN74PiOE7evCf0e1lS5EveqIGwgRCZT8wRFo_AE9F8Zd5O-UPvF4b-hRVkyBabhBQAO6tjnsS2XHEQuAkcUx855J8_iQfwmzHWtMy_X9bm_4k3RK-0Z7Uw7RB3i_5ihDnKSrpL1glQuYKpaELgNDDCnxWpIeZ-0x9tiDyMMiFfibtvPGYL2kubjpYDhfdCuZ-wX8s2XgNgr8Ep5sgH4d87xfv1mupSvv67HfY5jOeCb8gD_Dj5aDi6rsFORd52gI9nmSM6D5xNLg9w9DAlUbGzyhx0t5vkzB1VeRJYhHGR8AHCJM3inT5SeyJCc6CBVTf97_korQ",
  "valid_until": 1508718652
}
```

* User then presents his/her token to the appropriate endpoint on the GameServer:

```
16:30 $ http POST http://localhost:8081/join/564961a1-001d-46c0-806e-77a7e68ce461 'Authorization:eyJhbGciOiJSUzUxMiIsInNpZ19raWQiOiJiYjEzZmE3NC1kODNlLTQ1Y2UtYTVkZC1jZjQ3YjlkM2UzMjYiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJhZHJpYW5vc2VsYS9hbGwiLCJleHAiOjE1MDg3MTg2NTIsImp0aSI6IjhhZTU2YjUxLWRjMWYtNGY3Ny05ZDVkLTgwM2QyMTZlMDk2ZSIsImlhdCI6MTUwODcxNTA1MiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwibmJmIjoxNTA4NzE1MDUyLCJzdWIiOiI2MjgyMDk5OS0wMjVmLTQ4ZDItYTc4YS0wNDU1ZjEzNTVkMDMiLCJncnBzIjpbIjA2NjIwMDg0LWRmMjktNDM0OS04OGJiLTQxOThjMDViNDE1YiIsImQ1MTVjMDI3LWJlNGItNGFjMS05NzkxLWU4OWZiYjcxY2NjZiIsImEyM2Y3NjdlLTkyNjAtNDhkMy05ZDhkLTY4YzRlMzViNmY3MyJdfQ.Gch13sVDrng0eseN74PiOE7evCf0e1lS5EveqIGwgRCZT8wRFo_AE9F8Zd5O-UPvF4b-hRVkyBabhBQAO6tjnsS2XHEQuAkcUx855J8_iQfwmzHWtMy_X9bm_4k3RK-0Z7Uw7RB3i_5ihDnKSrpL1glQuYKpaELgNDDCnxWpIeZ-0x9tiDyMMiFfibtvPGYL2kubjpYDhfdCuZ-wX8s2XgNgr8Ep5sgH4d87xfv1mupSvv67HfY5jOeCb8gD_Dj5aDi6rsFORd52gI9nmSM6D5xNLg9w9DAlUbGzyhx0t5vkzB1VeRJYhHGR8AHCJM3inT5SeyJCc6CBVTf97_korQ'
HTTP/1.1 401 Unauthorized
Content-Length: 78
Content-Type: text/plain; charset=utf-8
Date: Sun, 22 Oct 2017 23:31:26 GMT

User 62820999-025f-48d2-a78a-0455f1355d03 is not in the GameServer users group
```

