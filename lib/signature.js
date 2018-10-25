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
      if( self.hasOwnProperty( k ) )
        self[ k ] = options[ k ]
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
    
    var value = ( input + '' ).replace( /\r\n\s/g, '' )
    var offset = 0
    var assignOffset = -1
    var delimiterOffset = -1
    var field = ''
    var fieldValue = ''

    while( offset < value.length ) {

      if( /\s/.test( value[ offset ] ) ) {
        offset++
        continue
      }

      assignOffset = value.indexOf( '=', offset + 1 )
      field = value.slice( offset, assignOffset )

      if( !Signature.keys.includes( field ) ) {
        throw new Error( `Unknown field name "${field}"` )
      }

      delimiterOffset = value.indexOf( ';', assignOffset + 1 )
      fieldValue = value.slice( assignOffset + 1, delimiterOffset !== -1 ? delimiterOffset : undefined )

      switch( Signature.fieldMap[ field ] ) {
        case 'signature':
        case 'hash':
          this[ Signature.fieldMap[ field ] ] = Buffer.from( fieldValue, 'base64' )
          break
        case 'headers':
        case 'copiedHeaders':
          this[ Signature.fieldMap[ field ] ] = fieldValue.split( ':' ).map( ( value ) => value.trim() )
          break
        default:
          this[ Signature.fieldMap[ field ] ] = fieldValue
          break
      }

      offset = delimiterOffset !== -1 ?
        delimiterOffset + 1 : value.length

    }

    return this

  },
  
  toString: function() {
    
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
