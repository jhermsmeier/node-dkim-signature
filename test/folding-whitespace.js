const assert = require( 'node:assert' )
const DKIMSignature = require( '..' )

context( 'Folding Whitespace', () => {

  test( 'tag value with leading FWS', () => {
    var expected = 'a=1234;b=5678;'
    var value = `a\r\n =\r\n 1234; \r\n b=5678;`
    assert.strictEqual( DKIMSignature.unfold( value ), expected )
  })

  test( 'tag value with leading and trailing FWS', () => {
    var expected = 'a=1234;b=5678;'
    var value = `a\r\n =\r\n 1234\r\n ; \r\n b=5678;`
    assert.strictEqual( DKIMSignature.unfold( value ), expected )
  })

  test( 'tag value with trailing FWS', () => {
    var expected = 'a=1234;b=5678;'
    var value = `a=1234 \r\n ;b=5678;`
    assert.strictEqual( DKIMSignature.unfold( value ), expected )
  })

  test( 'tag value with WSP', () => {
    var expected = 'a=1234 \nABCD;b=5678 EFGH;'
    var value = `a=1234 \nABCD\r\n ;b=5678 EFGH;`
    assert.strictEqual( DKIMSignature.unfold( value ), expected )
  })

})
