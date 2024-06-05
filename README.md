# DomainKeys Identified Mail (DKIM) Signature
[![npm](https://img.shields.io/npm/v/dkim-signature.svg?style=flat-square)](https://npmjs.com/dkim-signature)
[![npm](https://img.shields.io/npm/l/dkim-signature.svg?style=flat-square)](https://npmjs.com/dkim-signature)
[![npm downloads](https://img.shields.io/npm/dm/dkim-signature.svg?style=flat-square)](https://npmjs.com/dkim-signature)

## Install via [npm](https://npmjs.com)

```sh
$ npm install dkim-signature
```

## Usage

```js
const DKIMSignature = require( 'dkim-signature' )
```

### Parsing Signature Records

```js
const value = `v=1; a=rsa-sha256; c=relaxed/relaxed;\r
 d=example.test; s=20240605; i=@example.test;\r
 h=mime-version:date:message-id:subject:from:to:content-type;\r
 bh=DrlXO8ocnosZnW5ZN7P4S/fIdR8vwHj0TyzoPISZF2Q=;\r
 b=gOHBExs2JcJFRrozPDw88Js0dc0AHOo6YTZqrDTedfcK/jM/mxfu5rfVzuUnKAGiS5\r
 ZvRvXvwYjIW0B9t0DDHDOs5soIukuEXeUw9OV2QD8qc5pmOShuRQWyW5pRftTF87omkj\r
 gV2Eik5K2f8FpNlyvuLDjMUmyP8RpLaRrii6+kRRsoJzzP41IqALmlLmJfvtnkeu5kM0\r
 v4XnQ4hBNcaLuCmq3fZfCQFDexofECQOZ8FWE0VfdASG8HOJ6jgxuKwYtNfy11ySUSrI\r
 wFFlrjTfiNqSD9nzQns3j+xXLtqsvviJQXJgkC8O6mLel3GDwm8LHzBoszzqZ/FiL4rg\r
 Vdfw==\r
`
```

```js
const signature = DKIMSignature.parse( value )
```

```js
DKIMSignature {
  version: 1,
  algorithm: 'rsa-sha256',
  domain: 'example.test',
  selector: '20240605',
  identifier: '@example.test',
  queryMethods: [ 'dns/txt' ],
  canonicalization: [ 'relaxed', 'relaxed' ],
  headers: [
    'mime-version',
    'date',
    'message-id',
    'subject',
    'from',
    'to',
    'content-type'
  ],
  copiedHeaders: undefined,
  createdAt: undefined,
  expiresAt: undefined,
  bodyLength: undefined,
  bodyHash: 'DrlXO8ocnosZnW5ZN7P4S/fIdR8vwHj0TyzoPISZF2Q=',
  data: 'gOHBExs2JcJFRrozPDw88Js0dc0AHOo6YTZqrDTedfcK/jM/mxfu5rfVzuUnKAGiS5ZvRvXvwYjIW0B9t0DDHDOs5soIukuEXeUw9OV2QD8qc5pmOShuRQWyW5pRftTF87omkjgV2Eik5K2f8FpNlyvuLDjMUmyP8RpLaRrii6+kRRsoJzzP41IqALmlLmJfvtnkeu5kM0v4XnQ4hBNcaLuCmq3fZfCQFDexofECQOZ8FWE0VfdASG8HOJ6jgxuKwYtNfy11ySUSrIwFFlrjTfiNqSD9nzQns3j+xXLtqsvviJQXJgkC8O6mLel3GDwm8LHzBoszzqZ/FiL4rgVdfw==',
  unknownTags: undefined
}
```

### Stringifying

```js
const signature = new DKIMSignature({
  domain: 'example.test',
  selector: 'default',
  algorithm: 'rsa-sha256',
  headers: [ 'from', 'to', 'date', 'subject' ],
  bodyHash: '2jmj7l5rSw0yVb/vlWAYkK/YBwk=',
  data: '47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='
})
```

```console
> console.log( signature.toString() )
v=1; a=rsa-sha256; d=example.test; s=default; h=from:to:date:subject; bh=2jmj7l5rSw0yVb/vlWAYkK/YBwk=; b=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=
```
