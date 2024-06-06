const assert = require( 'node:assert' )
const DKIMSignature = require( '..' )

context( 'DKIMSignature', () => {

  context( 'Errors', () => {

    test( 'Duplicate tags', () => {

      assert.throws(() => {
        var value = 'v=1; v=2; a=rsa-sha1; d=example.test; s=default; h=from:to:subject:date; bh=2jmj7l5rSw0yVb/vlWAYkK/YBwk=; b=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='
        DKIMSignature.parse( value )
      }, /Invalid duplicate tag name/ )

    })

    test( 'Tag name case sensitivity', () => {

      assert.throws(() => {
        var value = 'V=1; a=rsa-sha1; d=example.test; s=default; h=from:to:subject:date; bh=2jmj7l5rSw0yVb/vlWAYkK/YBwk=; b=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='
        DKIMSignature.parse( value )
      }, /Missing version/ )

    })

    context( 'Required tags', () => {

      test( 'Missing / invalid / unknown version', () => {

        assert.throws(() => {
          var value = 'a=rsa-sha1; d=example.test; s=default; h=from:to:subject:date; bh=2jmj7l5rSw0yVb/vlWAYkK/YBwk=; b=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='
          DKIMSignature.parse( value )
        }, /Missing version/ )

        assert.throws(() => {
          var value = 'v=; a=rsa-sha1; d=example.test; s=default; h=from:to:subject:date; bh=2jmj7l5rSw0yVb/vlWAYkK/YBwk=; b=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='
          DKIMSignature.parse( value )
        }, /Invalid version/ )

        assert.throws(() => {
          var value = 'v=2; a=rsa-sha1; d=example.test; s=default; h=from:to:subject:date; bh=2jmj7l5rSw0yVb/vlWAYkK/YBwk=; b=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='
          DKIMSignature.parse( value )
        }, /Unknown version/ )

      })

      test( 'Missing algorithm', () => {

        assert.throws(() => {
          var value = 'v=1; d=example.test; s=default; h=from:to:subject:date; bh=2jmj7l5rSw0yVb/vlWAYkK/YBwk=; b=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='
          DKIMSignature.parse( value )
        }, /Missing algorithm/ )

        assert.throws(() => {
          var value = 'v=1; a=; d=example.test; s=default; h=from:to:subject:date; bh=2jmj7l5rSw0yVb/vlWAYkK/YBwk=; b=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='
          DKIMSignature.parse( value )
        }, /Missing algorithm/ )

      })

      test( 'Missing signature data', () => {

        assert.throws(() => {
          var value = 'v=1; a=rsa-sha1; d=example.test; s=default; h=from:to:subject:date; bh=2jmj7l5rSw0yVb/vlWAYkK/YBwk=;'
          DKIMSignature.parse( value )
        }, /Missing data/ )

        assert.throws(() => {
          var value = 'v=1; a=rsa-sha1; d=example.test; s=default; h=from:to:subject:date; bh=2jmj7l5rSw0yVb/vlWAYkK/YBwk=; b='
          DKIMSignature.parse( value )
        }, /Missing data/ )

      })

      test( 'Missing body hash', () => {

        assert.throws(() => {
          var value = 'v=1; a=rsa-sha1; d=example.test; s=default; h=from:to:subject:date; b=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='
          DKIMSignature.parse( value )
        }, /Missing body hash/ )

        assert.throws(() => {
          var value = 'v=1; a=rsa-sha1; d=example.test; s=default; h=from:to:subject:date; bh=; b=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='
          DKIMSignature.parse( value )
        }, /Missing body hash/ )

      })

      test( 'Missing selector', () => {

        assert.throws(() => {
          var value = 'v=1; a=rsa-sha1; d=example.test; h=from:to:subject:date; bh=2jmj7l5rSw0yVb/vlWAYkK/YBwk=; b=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='
          DKIMSignature.parse( value )
        }, /Missing selector/ )

        assert.throws(() => {
          var value = 'v=1; a=rsa-sha1; d=example.test; s=; h=from:to:subject:date; bh=2jmj7l5rSw0yVb/vlWAYkK/YBwk=; b=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='
          DKIMSignature.parse( value )
        }, /Missing selector/ )

      })

      test( 'Missing domain', () => {

        assert.throws(() => {
          var value = 'v=1; a=rsa-sha1; s=default; h=from:to:subject:date; bh=2jmj7l5rSw0yVb/vlWAYkK/YBwk=; b=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='
          DKIMSignature.parse( value )
        }, /Missing domain/ )

        assert.throws(() => {
          var value = 'v=1; a=rsa-sha1; d=; s=default; h=from:to:subject:date; bh=2jmj7l5rSw0yVb/vlWAYkK/YBwk=; b=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='
          DKIMSignature.parse( value )
        }, /Missing domain/ )

      })

      test( 'Missing header list', () => {

        assert.throws(() => {
          var value = 'v=1; a=rsa-sha1; d=example.test; s=default; bh=2jmj7l5rSw0yVb/vlWAYkK/YBwk=; b=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='
          DKIMSignature.parse( value )
        }, /Missing headers/ )

        assert.throws(() => {
          var value = 'v=1; a=rsa-sha1; d=example.test; s=default; h=; bh=2jmj7l5rSw0yVb/vlWAYkK/YBwk=; b=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='
          DKIMSignature.parse( value )
        }, /Missing headers/ )

      })

    })

    context( 'Invalid values', () => {

      test( 'Invalid tag name', () => {

        assert.throws(() => {
          var value = 'v=1; øl=beer; a=rsa-sha1; d=example.test; s=default; h=from:to:subject:date; bh=2jmj7l5rSw0yVb/vlWAYkK/YBwk=; b=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='
          DKIMSignature.parse( value )
        }, /Invalid character in tag name/ )

      })

      test( 'Invalid tag value', () => {

        assert.throws(() => {
          var value = 'v=1; beer=øl; a=rsa-sha1; d=example.test; s=default; h=from:to:subject:date; bh=2jmj7l5rSw0yVb/vlWAYkK/YBwk=; b=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='
          DKIMSignature.parse( value )
        }, /Invalid character in tag value/ )

      })

      test( 'Invalid creation timestamp', () => {

        assert.throws(() => {
          var value = 'v=1; t=-1; a=rsa-sha1; d=example.test; s=default; h=from:to:subject:date; bh=2jmj7l5rSw0yVb/vlWAYkK/YBwk=; b=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='
          DKIMSignature.parse( value )
        }, /Invalid timestamp value/ )

      })

      test( 'Invalid expiration timestamp', () => {

        assert.throws(() => {
          var value = 'v=1; x=-1; a=rsa-sha1; d=example.test; s=default; h=from:to:subject:date; bh=2jmj7l5rSw0yVb/vlWAYkK/YBwk=; b=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='
          DKIMSignature.parse( value )
        }, /Invalid timestamp value/ )

      })

      test( 'Invalid body length', () => {

        assert.throws(() => {
          var value = 'v=1; l=-1; a=rsa-sha1; d=example.test; s=default; h=from:to:subject:date; bh=2jmj7l5rSw0yVb/vlWAYkK/YBwk=; b=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='
          DKIMSignature.parse( value )
        }, /Invalid body length/ )

      })

      test( 'Invalid base64 data', () => {

        assert.throws(() => {
          var value = 'v=1; a=rsa-sha1; d=example.test; s=default; h=from:to:subject:date; bh=--; b=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='
          DKIMSignature.parse( value )
        }, /Invalid base64/ )

      })

    })

  })

})
