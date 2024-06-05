const assert = require( 'node:assert' )
const DKIMSignature = require( '..' )

context( 'DKIMSignature', function() {

  context( '.parse()', function() {

    test( 'Example 1', function() {

      var header = `v=1; a=rsa-sha256; d=example.net; s=brisbane;\r
      c=simple; q=dns/txt; i=@eng.example.net;\r
      t=1117574938; x=1118006938;\r
      h=from:to:subject:date;\r
      z=From:foo@eng.example.net|To:joe@example.com|\r
       Subject:demo=20run|Date:July=205,=202005=203:44:08=20PM=20-0700;\r
      bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=;\r
      b=dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZVoG4ZHRNiYzR`

      var signature = DKIMSignature.parse( header )

    })

    test( 'Google Mail', function() {

      var header = `v=1; a=rsa-sha256; c=relaxed/relaxed;\r
       d=gmail.com; s=20120113;\r
       h=mime-version:date:message-id:subject:from:to:content-type;\r
       bh=DrlXO8ocnosZnW5ZN7P4S/fIdR8vwHj0TyzoPISZF2Q=;\r
       b=gOHBExs2JcJFRrozPDw88Js0dc0AHOo6YTZqrDTedfcK/jM/mxfu5rfVzuUnKAGiS5\r
       ZvRvXvwYjIW0B9t0DDHDOs5soIukuEXeUw9OV2QD8qc5pmOShuRQWyW5pRftTF87omkj\r
       gV2Eik5K2f8FpNlyvuLDjMUmyP8RpLaRrii6+kRRsoJzzP41IqALmlLmJfvtnkeu5kM0\r
       v4XnQ4hBNcaLuCmq3fZfCQFDexofECQOZ8FWE0VfdASG8HOJ6jgxuKwYtNfy11ySUSrI\r
       wFFlrjTfiNqSD9nzQns3j+xXLtqsvviJQXJgkC8O6mLel3GDwm8LHzBoszzqZ/FiL4rg\r
       Vdfw==`

      var signature = DKIMSignature.parse( header )

      assert.ok( signature )
      assert.equal( signature.algorithm, 'rsa-sha256' )
      assert.deepEqual( signature.canonicalization, [ 'relaxed', 'relaxed' ] )
      assert.equal( signature.domain, 'gmail.com' )
      assert.deepEqual( signature.queryMethods, [ 'dns/txt' ] )
      assert.equal( signature.selector, '20120113' )
      assert.equal( signature.version, '1' )
      assert.deepEqual( signature.headers, [
        'mime-version',
        'date',
        'message-id',
        'subject',
        'from',
        'to',
        'content-type'
      ])

    })

    test( 'Google Mail with "dara"', function() {

      var header = `v=1; a=rsa-sha256; c=relaxed/relaxed;\r
       d=gmail.com; s=20120113; dara=google.com; \r
       h=mime-version:date:message-id:subject:from:to:content-type;\r
       bh=DrlXO8ocnosZnW5ZN7P4S/fIdR8vwHj0TyzoPISZF2Q=;\r
       b=gOHBExs2JcJFRrozPDw88Js0dc0AHOo6YTZqrDTedfcK/jM/mxfu5rfVzuUnKAGiS5\r
       ZvRvXvwYjIW0B9t0DDHDOs5soIukuEXeUw9OV2QD8qc5pmOShuRQWyW5pRftTF87omkj\r
       gV2Eik5K2f8FpNlyvuLDjMUmyP8RpLaRrii6+kRRsoJzzP41IqALmlLmJfvtnkeu5kM0\r
       v4XnQ4hBNcaLuCmq3fZfCQFDexofECQOZ8FWE0VfdASG8HOJ6jgxuKwYtNfy11ySUSrI\r
       wFFlrjTfiNqSD9nzQns3j+xXLtqsvviJQXJgkC8O6mLel3GDwm8LHzBoszzqZ/FiL4rg\r
       Vdfw==`

      var signature = DKIMSignature.parse( header )

      assert.ok( signature )
      assert.equal( signature.algorithm, 'rsa-sha256' )
      assert.deepEqual( signature.canonicalization, [ 'relaxed', 'relaxed' ] )
      assert.equal( signature.domain, 'gmail.com' )
      assert.deepEqual( signature.queryMethods, [ 'dns/txt' ] )
      assert.equal( signature.selector, '20120113' )
      assert.equal( signature.version, '1' )
      assert.deepEqual( signature.headers, [
        'mime-version',
        'date',
        'message-id',
        'subject',
        'from',
        'to',
        'content-type'
      ])

    })

    test( 'Google Mail with "darn"', function() {

      var header = `v=1; a=rsa-sha256; c=relaxed/relaxed;\r
       d=gmail.com; s=20120113; darn=google.com; \r
       h=mime-version:date:message-id:subject:from:to:content-type;\r
       bh=DrlXO8ocnosZnW5ZN7P4S/fIdR8vwHj0TyzoPISZF2Q=;\r
       b=gOHBExs2JcJFRrozPDw88Js0dc0AHOo6YTZqrDTedfcK/jM/mxfu5rfVzuUnKAGiS5\r
       ZvRvXvwYjIW0B9t0DDHDOs5soIukuEXeUw9OV2QD8qc5pmOShuRQWyW5pRftTF87omkj\r
       gV2Eik5K2f8FpNlyvuLDjMUmyP8RpLaRrii6+kRRsoJzzP41IqALmlLmJfvtnkeu5kM0\r
       v4XnQ4hBNcaLuCmq3fZfCQFDexofECQOZ8FWE0VfdASG8HOJ6jgxuKwYtNfy11ySUSrI\r
       wFFlrjTfiNqSD9nzQns3j+xXLtqsvviJQXJgkC8O6mLel3GDwm8LHzBoszzqZ/FiL4rg\r
       Vdfw==`

      var signature = DKIMSignature.parse( header )

      assert.ok( signature )
      assert.equal( signature.algorithm, 'rsa-sha256' )
      assert.deepEqual( signature.canonicalization, [ 'relaxed', 'relaxed' ] )
      assert.equal( signature.domain, 'gmail.com' )
      assert.deepEqual( signature.queryMethods, [ 'dns/txt' ] )
      assert.equal( signature.selector, '20120113' )
      assert.equal( signature.version, '1' )
      assert.deepEqual( signature.headers, [
        'mime-version',
        'date',
        'message-id',
        'subject',
        'from',
        'to',
        'content-type'
      ])

    })

    test( 'Mandrill Mail With Spaces', function() {

      var header = `v=1; a=rsa-sha256; c=relaxed/relaxed; d=mandrillapp.com;\r
      i=@mandrillapp.com; q=dns/txt; s=mandrill; t=1508540429; h=From :\r
      Sender : Subject : To : Message-Id : Date : MIME-Version : Content-Type\r
      : From : Subject : Date : X-Mandrill-User : List-Unsubscribe;\r
      bh=ETZ1UqfGj/jZdVFwmNQQZ62c8njGJ6eC7j3Hpr7A6Ao=;\r
      b=GDtwx8ATyFwiQZ/wqz8MTyaYaEFZ5MmDhD4X+0oCK5+FTko9yl2cnC+w+7OxkysOIfxopd /fdkH1Ads3fqNyB88pegcoV07cT2UxFMFmlebzn7lV8PJY26lqqesf7qLSoZlR5PwzeFiIU4 UEm6Gbvw4LGpnKdL2+T9hgAD+4mVM=`

      var signature = DKIMSignature.parse( header )

      assert.ok( signature )
      assert.equal( signature.algorithm, 'rsa-sha256' )
      assert.deepEqual( signature.canonicalization, [ 'relaxed', 'relaxed' ] )
      assert.equal( signature.domain, 'mandrillapp.com' )
      assert.deepEqual( signature.queryMethods, [ 'dns/txt' ] )
      assert.equal( signature.selector, 'mandrill' )
      assert.equal( signature.version, '1' )
      assert.deepEqual( signature.headers, [
        'from',
        'sender',
        'subject',
        'to',
        'message-id',
        'date',
        'mime-version',
        'content-type',
        'from',
        'subject',
        'date',
        'x-mandrill-user',
        'list-unsubscribe'
      ])

    })

  })

})
