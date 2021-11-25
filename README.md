[![Build Status](https://img.shields.io/badge/build-passing-green)](https://img.shields.io/badge/build-passing-green) [![Code Size](https://img.shields.io/github/languages/code-size/Tanmoy-Barua/sql-sanitizer)](https://img.shields.io/github/languages/code-size/Tanmoy-Barua/sql-sanitizer)


sql-sanitizer
=============

Here the express module detects SQL injection attacks and stops them by sending 403 as a response.
The module checks the query string, route parameters, and body for any SQL injection-related contents.

```js
let app = express();
let sqlSanitizer = require('sql-sanitizer');
app.use(sqlSanitizer);
```

## Installation

    $ npm install sql-sanitizer


## Usage

Example:

```js
let express = require('express');
let app = express();
let sqlSanitizer = require('sql-sanitizer');
app.use(sqlSanitizer);

app.post('/route1', (req, res) => {
    res.status(200).send({});
});
app.get('/route2/:uid', (req, res) => {
    res.status(200).send({});
});
app.post('/route3', (req, res) => {
   res.status(200).send({});
});

app.listen(4000);
```