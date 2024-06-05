const assert = require( 'node:assert' )
const DKIMSignature = require( '..' )

context( 'DKIMSignature', () => {

  context( '#toString()', () => {

    context( 'domain', () => {

      test( 'case normalization', () => {

        var header = 'v=1; a=rsa-sha1; d=EXAMPLE.com; s=default; h=from:to:subject:date; bh=2jmj7l5rSw0yVb/vlWAYkK/YBwk=; b=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='
        var expected = 'v=1; a=rsa-sha1; d=example.com; s=default; h=from:to:subject:date; bh=2jmj7l5rSw0yVb/vlWAYkK/YBwk=; b=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='
        var signature = DKIMSignature.parse( header )

        assert.strictEqual( signature.toString(), expected )

      })

      test( 'internationalized domain name', () => {

        var expected = 'v=1; a=rsa-sha1; d=example.xn--jxalpdlp; s=xn--kxae4bafwg; h=from:to:subject:date; bh=; b='
        var signature = new DKIMSignature()

        signature.algorithm = 'rsa-sha1'
        signature.domain = 'example.δοκιμή'
        signature.selector = 'ουτοπία'
        signature.headers = [ 'from', 'to', 'subject', 'date' ]
        signature.bodyHash = Buffer.alloc( 0 )
        signature.data = Buffer.alloc( 0 )

        assert.strictEqual( signature.toString(), expected )

      })

      test( 'numeric selector subdomain', () => {

        var expected = 'v=1; a=rsa-sha1; d=20120113.org; s=20120113; h=from:to:subject:date; bh=; b='
        var signature = new DKIMSignature()

        signature.algorithm = 'rsa-sha1'
        signature.domain = '20120113.org'
        signature.selector = '20120113'
        signature.headers = [ 'from', 'to', 'subject', 'date' ]
        signature.bodyHash = Buffer.alloc( 0 )
        signature.data = Buffer.alloc( 0 )

        assert.strictEqual( signature.toString(), expected )

      })

    })

    context( 'canonicalization', () => {

      test( 'omitted default', () => {

        var header = 'v=1; a=rsa-sha1; d=dkim.example; s=default; h=from:to:subject:date; bh=2jmj7l5rSw0yVb/vlWAYkK/YBwk=; b=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='
        var signature = DKIMSignature.parse( header )

        assert.strictEqual( signature.toString(), header )

      })

      test( 'omitted default body', () => {

        var header = 'v=1; a=rsa-sha1; d=dkim.example; s=default; c=relaxed; h=from:to:subject:date; bh=2jmj7l5rSw0yVb/vlWAYkK/YBwk=; b=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='
        var signature = DKIMSignature.parse( header )

        assert.strictEqual( signature.toString(), header )

      })

      test( 'no omission', () => {

        var header = 'v=1; a=rsa-sha1; d=dkim.example; s=default; c=simple/relaxed; h=from:to:subject:date; bh=2jmj7l5rSw0yVb/vlWAYkK/YBwk=; b=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='
        var signature = DKIMSignature.parse( header )

        assert.strictEqual( signature.toString(), header )

        var header = 'v=1; a=rsa-sha1; d=dkim.example; s=default; c=relaxed/relaxed; h=from:to:subject:date; bh=2jmj7l5rSw0yVb/vlWAYkK/YBwk=; b=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='
        var signature = DKIMSignature.parse( header )

        assert.strictEqual( signature.toString(), header )

      })

    })

  })

})
