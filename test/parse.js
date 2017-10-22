var DKIMSignature = require( '..' )
var assert = require( 'assert' )

suite( 'DKIMSignature', function() {
  
  suite( '.parse()', function() {
    
    test( 'Google Mail', function() {
      
      var header = `v=1; a=rsa-sha256; c=relaxed/relaxed;
       d=gmail.com; s=20120113;
       h=mime-version:date:message-id:subject:from:to:content-type;
       bh=DrlXO8ocnosZnW5ZN7P4S/fIdR8vwHj0TyzoPISZF2Q=;
       b=gOHBExs2JcJFRrozPDw88Js0dc0AHOo6YTZqrDTedfcK/jM/mxfu5rfVzuUnKAGiS5
       ZvRvXvwYjIW0B9t0DDHDOs5soIukuEXeUw9OV2QD8qc5pmOShuRQWyW5pRftTF87omkj
       gV2Eik5K2f8FpNlyvuLDjMUmyP8RpLaRrii6+kRRsoJzzP41IqALmlLmJfvtnkeu5kM0
       v4XnQ4hBNcaLuCmq3fZfCQFDexofECQOZ8FWE0VfdASG8HOJ6jgxuKwYtNfy11ySUSrI
       wFFlrjTfiNqSD9nzQns3j+xXLtqsvviJQXJgkC8O6mLel3GDwm8LHzBoszzqZ/FiL4rg
       Vdfw==`
      
      var signature = DKIMSignature.parse( header )
      
      assert.ok( signature )
      assert.equal( signature.algorithm, 'rsa-sha256' )
      assert.equal( signature.canonical, 'relaxed/relaxed' )
      assert.equal( signature.domain, 'gmail.com' )
      assert.equal( signature.query, 'dns/txt' )
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
      
      var header = `v=1; a=rsa-sha256; c=relaxed/relaxed; d=mandrillapp.com;
      i=@mandrillapp.com; q=dns/txt; s=mandrill; t=1508540429; h=From :
      Sender : Subject : To : Message-Id : Date : MIME-Version : Content-Type
      : From : Subject : Date : X-Mandrill-User : List-Unsubscribe;
      bh=ETZ1UqfGj/jZdVFwmNQQZ62c8njGJ6eC7j3Hpr7A6Ao=;
      b=GDtwx8ATyFwiQZ/wqz8MTyaYaEFZ5MmDhD4X+0oCK5+FTko9yl2cnC+w+7OxkysOIfxopd /fdkH1Ads3fqNyB88pegcoV07cT2UxFMFmlebzn7lV8PJY26lqqesf7qLSoZlR5PwzeFiIU4 UEm6Gbvw4LGpnKdL2+T9hgAD+4mVM=`
      
      var signature = DKIMSignature.parse( header )
      
      assert.ok( signature )
      assert.equal( signature.algorithm, 'rsa-sha256' )
      assert.equal( signature.canonical, 'relaxed/relaxed' )
      assert.equal( signature.domain, 'mandrillapp.com' )
      assert.equal( signature.query, 'dns/txt' )
      assert.equal( signature.selector, 'mandrill' )
      assert.equal( signature.version, '1' )
      assert.deepEqual( signature.headers, [
        'From',
        'Sender',
        'Subject',
        'To',
        'Message-Id',
        'Date',
        'MIME-Version',
        'Content-Type',
        'subject',
        'From',
        'Subject',
        'Date',
        'X-Mandrill-User',
        'List-Unsubscribe'
      ])
      
    })


  })
  
})
