/**
 * Signature Constructor
 * @return {Signature}
 */
function Signature( options ) {
  
  if( !(this instanceof Signature) )
    return new Signature( options )
  
  // Signing algorithm
  this.algorithm     = 'rsa-sha256'
  // Headers canonicalization / normalization type
  this.canonical     = 'simple'
  this.copiedHeaders = []
  // Signing domain
  this.domain        = null
  this.expires       = null
  this.hash          = null
  // Headers
  this.headers       = []
  this.identity      = null
  this.length        = null
  this.query         = 'dns/txt'
  this.selector      = null
  // DKIM Signature data (base64)
  this.signature     = null
  this.timestamp     = null
  // DKIM version
  this.version       = '1'
  
  var self = this
  
  if( options != null ) {
    Object.keys( options ).forEach( function( k, v ) {
      if( Signature.fields.indexOf( k ) !== -1 ) {
        self[ k ] = options[ k ]
      }
    })
  }
  
}

Signature.fields = [
  'algorithm',
  'canonical',
  'copiedHeaders',
  'domain',
  'expires',
  'hash',
  'headers',
  'identity',
  'length',
  'query',
  'selector',
  'signature',
  'timestamp',
  'version',
]

Signature.keys = [
  'a', // algorithm
  'c', // canonical
  'z', // copiedHeaders
  'd', // domain
  'x', // expires
  'bh', // body hash
  'h', // headers
  'i', // identity
  'l', // length
  'q', // query
  's', // selector
  'b', // signature
  't', // timestamp
  'v', // version
]

Signature.fieldMap = Signature.keys.reduce( function( map, key, i ) {
  map[ key ] = Signature.fields[ i ]
  return map
}, {})

Signature.create = function( options ) {
  return new Signature( options )
}

Signature.parse = function( dkimHeader ) {
  return new Signature().parse( dkimHeader )
}

function splitArray( value ) {
  
  var list = []
  var offset = 0
  var delimiterOffset = -1
  
  while( offset < value.length ) {
    delimiterOffset = value.indexOf( ':', offset )
    delimiterOffset = delimiterOffset !== -1 ? delimiterOffset : value.length
    list.push( value.slice( offset, delimiterOffset ).trim() )
    offset = delimiterOffset + 1
  }
  
  return list
  
}

/**
 * Signature Prototype
 * @type {Object}
 */
Signature.prototype = {
  
  constructor: Signature,
  
  /**
   * Parse a DKIM Signature from a String or Buffer
   * @param {String|Buffer} input
   * @returns {Signature}
   */
  parse( input ) {
    
    var value = ( input + '' ).replace( /\r?\n\s/g, '' )
    var offset = 0
    var assignOffset = -1
    var delimiterOffset = -1
    var field = ''
    var fieldName = ''
    var fieldValue = ''

    while( offset < value.length ) {

      if( /\s/.test( value[ offset ] ) ) {
        offset++
        continue
      }

      assignOffset = value.indexOf( '=', offset + 1 )
      field = value.slice( offset, assignOffset )

      if( Signature.keys.indexOf( field ) === -1 ) {
        throw new Error( `Unknown field name "${field}"` )
      }

      fieldName = Signature.fieldMap[ field ]
      delimiterOffset = value.indexOf( ';', assignOffset + 1 )
      fieldValue = value.slice( assignOffset + 1, delimiterOffset !== -1 ? delimiterOffset : undefined )

      if( fieldName === 'signature' || fieldName === 'hash' ) {
        this[ fieldName ] = Buffer.from( fieldValue, 'base64' )
      } else if( fieldName === 'headers' || fieldName === 'copiedHeaders' ) {
        this[ fieldName ] = splitArray( fieldValue )
      } else {
        this[ fieldName ] = fieldValue
      }

      offset = delimiterOffset !== -1 ?
        delimiterOffset + 1 : value.length

    }

    return this

  },
  
  toString() {
    
    var self = this
    
    return Signature.fields.map( function( field, i ) {
      if( typeof self[ field ] === 'string' || typeof self[ field ] === 'number' ) {
        return Signature.keys[ i ] + '=' + self[ field ]
      } else if( Array.isArray( self[ field ] ) && self[ field ].length ) {
        return Signature.keys[ i ] + '=' + self[ field ].join( ':' )
      } else if( Buffer.isBuffer( self[ field ] ) && self[ field ].length ) {
        return Signature.keys[ i ] + '=' + self[ field ].toString( 'base64' )
      }
    })
    .filter( function( field ) {
      return field != null
    })
    .join( '; ' )
    
  }
  
}

// Exports
module.exports = Signature
