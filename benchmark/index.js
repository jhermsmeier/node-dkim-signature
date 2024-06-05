var bench = require( 'nanobench' )
var DKIMSignature = require( '..' )

const ITERATIONS = 1000000

const header = `v=1; a=rsa-sha256; c=relaxed/relaxed;\r
 d=gmail.com; s=20120113;\r
 h=mime-version:date:message-id:subject:from:to:content-type;\r
 bh=DrlXO8ocnosZnW5ZN7P4S/fIdR8vwHj0TyzoPISZF2Q=;\r
 b=gOHBExs2JcJFRrozPDw88Js0dc0AHOo6YTZqrDTedfcK/jM/mxfu5rfVzuUnKAGiS5\r
 ZvRvXvwYjIW0B9t0DDHDOs5soIukuEXeUw9OV2QD8qc5pmOShuRQWyW5pRftTF87omkj\r
 gV2Eik5K2f8FpNlyvuLDjMUmyP8RpLaRrii6+kRRsoJzzP41IqALmlLmJfvtnkeu5kM0\r
 v4XnQ4hBNcaLuCmq3fZfCQFDexofECQOZ8FWE0VfdASG8HOJ6jgxuKwYtNfy11ySUSrI\r
 wFFlrjTfiNqSD9nzQns3j+xXLtqsvviJQXJgkC8O6mLel3GDwm8LHzBoszzqZ/FiL4rg\r
 Vdfw==`

bench( `DKIMSignature#parse() ⨉ ${ITERATIONS}`, function( run ) {
  
  var signature = null
  
  run.start()
  for( var i = 0; i < ITERATIONS; i++ ) {
    signature = DKIMSignature.parse( header )
  }
  run.end()
  
})

bench( `DKIMSignature#toString() ⨉ ${ITERATIONS}`, function( run ) {
  
  var signature = DKIMSignature.parse( header )
  var output = ''
  
  run.start()
  for( var i = 0; i < ITERATIONS; i++ ) {
    output = signature.toString()
  }
  run.end()
  
})
