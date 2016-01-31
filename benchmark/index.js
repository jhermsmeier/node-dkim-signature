var DKIMSignature = require( '..' )
var assert = require( 'assert' )

suite( 'DKIMSignature', function() {
  
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
  
  bench( '.parse()', function() {
    var signature = DKIMSignature.parse( header )
  })
  
  bench( '.toString()', function() {
    var signature = DKIMSignature.parse( header )
  })
  
})
