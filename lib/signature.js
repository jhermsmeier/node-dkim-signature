const url = require( 'node:url' )
const quotedPrintable = require( 'dkim-quoted-printable' )

// NOTE: Excludes allowed leading and trailing FWS;
// Tag names should be unfolded and trimmed before
// testing against this pattern
// @see https://datatracker.ietf.org/doc/html/rfc6376#section-3.2
const TAG_NAME_PATTERN = /^[a-zA-Z][a-zA-Z0-9_]*$/

// NOTE: Excludes FWS; Values should be unfolded and
// trimmed before testing against this pattern
// @see https://datatracker.ietf.org/doc/html/rfc6376#section-3.2
const TAG_VALUE_PATTERN = /^[\x09\x20\x21-\x3A\x3C-\x7E]*$/

// NOTE: Excludes any whitespace; value should be unfolded and
// trimmed before testing against this pattern
// ALPHADIGITPS = (ALPHA / DIGIT / "+" / "/")
// base64string = ALPHADIGITPS *([FWS] ALPHADIGITPS) [ [FWS] "=" [ [FWS] "=" ] ]
const BASE64_PATTERN = /^[A-Z0-9+\/\-]+[=]*$/i

// String#trim() trims too many characters
// for what is allowed by DKIM (WSP = SP / HTAB)
function trimWhitespace( value ) {
  return value.replace( /^[\x09\x20]+|[\x09\x20]+$/g, '' )
}

// Because `url.domainToASCII()` parses numeric inputs
// as IPv4 addresses in disguise, we need to circumvent that
// in order to do this for numeric subdomains
// NOTE: `url.domainToASCII()` returns an empty string for
// invalid domains instead of throwing an error
// @see https://nodejs.org/api/url.html#urldomaintoasciidomain
function subdomainToASCII( value ) {
  return url.domainToASCII( `${value}.test` ).slice( 0, -5 )
}

class DKIMSignature {

  /**
   * REQUIRED. Version. Defines the version of the DKIM specification
   * that applies to the signature record. Defaults to "1".
   * @type {Number}
   */
  version = 1
  /**
   * REQUIRED. Algorithm used to generate the signature.
   * Verifiers MUST support "rsa-sha1" and "rsa-sha256";
   * Signers SHOULD sign using "rsa-sha256".
   * @type {String|undefined}
   */
  algorithm = undefined
  /**
   * REQUIRED. Domain claiming responsibility for an
   * introduction of a message into the mail stream.
   * @type {String|undefined}
   */
  domain = undefined
  /**
   * REQUIRED. Selector subdividing the namespace for domain tag.
   * @type {String|undefined}
   */
  selector = undefined
  /**
   * OPTIONAL. Agent or User Identifier (AUID).
   * Default is an empty local-partfollowed by an "@"
   * followed by the domain from the "d=" tag
   * @type {String|undefined}
   */
  identifier = undefined
  /**
   * OPTIONAL. List of query methods used to retrieve the public key.
   * Default is `[ 'dns/txt' ]`.
   * @type {Array<String>}
   */
  queryMethods = [ 'dns/txt' ]
  /**
   * OPTIONAL. Message part canonicalization for header & body respectively.
   * Default is `[ 'simple', 'simple' ]`.
   * @type {Array}
   */
  canonicalization = [ 'simple', 'simple' ]
  /**
   * REQUIRED. List of signed header fields.
   * @type {Array<String>}
   */
  headers = undefined
  /**
   * OPTIONAL. List of copied header fields.
   * @type {Array<String>}
   */
  copiedHeaders = undefined
  /**
   * OPTIONAL. Signature creation timestamp.
   * RECOMMENDED. Default is an unknown creation time.
   * @type {Date|undefined}
   */
  createdAt = undefined
  /**
   * OPTIONAL. Signature expiration timestamp.
   * RECOMMENDED. Default is no expiration.
   * @type {Date|undefined}
   */
  expiresAt = undefined
  /**
   * OPTIONAL. Length of the body (in bytes) that is hashed.
   * Default is entire body.
   * @type {Number|undefined}
   */
  bodyLength = undefined
  /**
   * REQUIRED. Hash of the canonicalized body part of
   * the message as limited by the "l=" tag; base64-encoded.
   * @type {String|undefined}
   */
  bodyHash = undefined
  /**
   * REQUIRED. Signature data; base64-encoded.
   * @type {String|undefined}
   */
  data = undefined
  /**
   * Map of unknown / unsupported signature record tags, if present.
   * @type {Map<String,String>|undefined}
   */
  unknownTags = undefined

  /**
   * Create a new DKIMSignature
   * @param {Object} [options]
   * @param {Number} [options.version=1]
   * @param {String} [options.algorithm]
   * @param {String} [options.domain]
   * @param {String} [options.selector]
   * @param {String} [options.identifier]
   * @param {Array<String>} [options.queryMethods=[ 'dns/txt' ]]
   * @param {Array<String>} [options.canonicalization=[ 'simple', 'simple' ]]
   * @param {Array<String>} [options.headers]
   * @param {Array<String>} [options.copiedHeaders]
   * @param {String|Number|Date} [options.createdAt]
   * @param {String|Number|Date} [options.expiresAt]
   * @param {Number} [options.bodyLength]
   * @param {Buffer|String} [options.bodyHash]
   * @param {Buffer|String} [options.data]
   */
  constructor( options ) {
    if( options != null ) {
      if( options.version ) this.version = Number( options.version )
      if( options.algorithm ) this.algorithm = options.algorithm
      if( options.data ) {
        this.data = Buffer.isBuffer( options.data )
          ? options.data.toString( 'base64' )
          : options.data
      }
      if( options.bodyHash ) {
        this.bodyHash = Buffer.isBuffer( options.bodyHash )
          ? options.bodyHash.toString( 'base64' )
          : options.bodyHash
      }
      if( options.bodyLength ) this.bodyLength = Number( options.bodyLength )
      if( options.queryMethods ) this.queryMethods = [].concat( this.queryMethods )
      if( options.canonicalization ) this.canonicalization = [].concat( this.canonicalization )
      if( options.identifier ) this.identifier = options.identifier
      if( options.selector ) this.selector = options.selector
      if( options.createdAt ) this.createdAt = new Date( options.createdAt )
      if( options.expiresAt ) this.expiresAt = new Date( options.expiresAt )
      if( options.domain ) this.domain = options.domain
      if( options.headers ) this.headers = [].concat( options.headers )
      if( options.copiedHeaders ) this.copiedHeaders = [].concat( options.copiedHeaders )
    }
  }

  static Error = class DKIMSignatureError extends Error {
    constructor( message ) {
      super( message )
    }
  }

  /**
   * @internal Unfold folding whitespace (FWS = [*WSP CRLF] 1*WSP)
   * @param {String} value
   * @returns {String}
   */
  static unfold( value ) {
    return String( value ).replace( /[\x09\x20]*\r\n[\x09\x20]/g, '' )
      .replace( /\r\n$/, '' ) // Also strip trailing CRLF
  }

  /**
   * @internal Test whether a tag name contains only valid characters
   * @param {String} value
   * @returns {Boolean}
   */
  static isValidTagName( value ) {
    return TAG_NAME_PATTERN.test( value )
  }

  /**
   * @internal Test whether a tag value contains only valid characters
   * @param {String} value
   * @returns {Boolean}
   */
  static isValidTagValue( value ) {
    return TAG_VALUE_PATTERN.test( value )
  }

  /**
   * @internal Test whether a tag value contains only valid base64 characters
   * @see https://datatracker.ietf.org/doc/html/rfc6376#section-2.10
   * @param {String} value
   * @returns {Boolean}
   */
  static isValidBase64( value ) {
    return BASE64_PATTERN.test( value )
  }

  /**
   * @internal Parse a timestamp value
   * @param {String} tagValue
   * @returns {Date}
   * @throws DKIMSignature.Error
   */
  static parseTimestamp( tagValue ) {
    if( !tagValue ) return undefined
    var timestamp = Number( tagValue )
    if( !Number.isInteger( timestamp ) || timestamp < 0 )
      throw new DKIMSignature.Error( 'Invalid timestamp value' )
    return new Date( timestamp * 1000 )
  }

  /**
   * @internal Parse the body length value
   * @param {String} tagValue
   * @returns {Number}
   * @throws DKIMSignature.Error
   */
  static parseBodyLength( tagValue ) {
    if( !tagValue ) return undefined
    var value = Number( tagValue )
    if( !Number.isInteger( value ) || value < 0 )
      throw new DKIMSignature.Error( 'Invalid body length' )
    return value
  }

  /**
   * @internal Parse a colon (":") separated list
   * @param {String} tagValue
   * @returns {Array<String>}
   */
  static parseColonList( tagValue ) {
    if( !tagValue ) return []
    return tagValue.split( /[\x09\x20]*:[\x09\x20]*/g )
  }

  /**
   * @internal Parse the copied-headers list
   * @param {String} tagValue
   * @returns {Array<String>}
   */
  static parseCopiedHeaders( tagValue ) {
    if( !tagValue ) return []
    return tagValue.split( /[\x09\x20]*\|[\x09\x20]*/g )
      .map( header => quotedPrintable.decode( header ) )
  }

  /**
   * @internal Parse the canonicalization methods list
   * @param {String} tagValue
   * @returns {Array<String>}
   */
  static parseCanonicalization( tagValue ) {
    if( !tagValue ) return [ 'simple', 'simple' ]
    var parts = tagValue.toLowerCase().split( '/' )
    return [ parts[0], parts[1] || 'simple' ]
  }

  /**
   * @internal Normalize and validate a base64 string
   * @param {String} tagValue
   * @returns {String}
   */
  static normalizeBase64( tagValue ) {

    // Strip all whitespace
    var value = tagValue.replace( /\s+/g, '' )
    if( !value ) return undefined

    if( !DKIMSignature.isValidBase64( value ) ) {
      throw new DKIMSignature.Error( 'Invalid base64 data' )
    }
    
    return value

  }

  /**
   * Parse a DKIM signature header value
   * @param {String|Buffer} value
   * @returns {DKIMSignature}
   * @throws {DKIMSignature.Error} If the header is invalid / malformed
   * @throws {TypeError} If argument type are incorrect
   */
  static parse( value ) {

    if( typeof value != 'string' && !Buffer.isBuffer( value ) )
      throw new TypeError( 'DKIM-Signature: Value must be a string or buffer' )

    value = DKIMSignature.unfold( value )

    var offset = 0
    var length = value.length
    var sig = new DKIMSignature()
    var tags = new Set()
    var hasVersionTag = false

    while( offset < length ) {

      let eot = value.indexOf( '=', offset )
      if( eot == -1 ) {
        throw new DKIMSignature.Error( 'Missing expected tag value delimiter' )
      }

      let tagName = trimWhitespace( value.slice( offset, eot ) )

      offset = eot + 1

      if( !DKIMSignature.isValidTagName( tagName ) ) {
        throw new DKIMSignature.Error( 'Invalid character in tag name' )
      }

      let eon = value.indexOf( ';', offset )
      if( eon == -1 ) eon = length

      let tagValue = trimWhitespace( value.slice( offset, eon ) )

      offset = eon + 1

      if( !DKIMSignature.isValidTagValue( tagValue ) ) {
        throw new DKIMSignature.Error( 'Invalid character in tag value' )
      }

      // Tags with duplicate names MUST NOT occur within a single tag-list; if
      // a tag name occurs more than once, the entire tag-list is invalid.
      // @see https://datatracker.ietf.org/doc/html/rfc6376#section-3.2
      if( tags.has( tagName ) ) {
        throw new DKIMSignature.Error( 'Invalid duplicate tag name' )
      } else {
        tags.add( tagName )
      }

      switch( tagName ) {
        case  'a': sig.algorithm = tagValue.toLowerCase(); break
        case  'c': sig.canonicalization = DKIMSignature.parseCanonicalization( tagValue ); break
        case  'z': sig.copiedHeaders = DKIMSignature.parseCopiedHeaders( tagValue ); break
        case  'd': sig.domain = url.domainToASCII( tagValue ); break
        case  'x': sig.expiresAt = DKIMSignature.parseTimestamp( tagValue ); break
        case 'bh': sig.bodyHash = DKIMSignature.normalizeBase64( tagValue ); break
        case  'h': sig.headers = DKIMSignature.parseColonList( tagValue.toLowerCase() ); break
        case  'i': sig.identifier = quotedPrintable.decode( tagValue ); break
        case  'l': sig.bodyLength = DKIMSignature.parseBodyLength( tagValue ); break
        case  'q': sig.queryMethods = DKIMSignature.parseColonList( tagValue.toLowerCase() ); break
        case  's': sig.selector = subdomainToASCII( tagValue ); break
        case  'b': sig.data = DKIMSignature.normalizeBase64( tagValue ); break
        case  't': sig.createdAt = DKIMSignature.parseTimestamp( tagValue ); break
        case  'v':
          sig.version = tagValue ? Number( tagValue ) : null
          hasVersionTag = true
          break
        default: // Unknown tag (ignore, but store)
          sig.unknownTags = sig.unknownTags ?? new Map()
          sig.unknownTags.set( tagName, tagValue )
          break
      }

    }

    if( !hasVersionTag )
      throw new DKIMSignature.Error( 'Missing version' )
    if( !Number.isInteger( sig.version ) )
      throw new DKIMSignature.Error( 'Invalid version' )
    if( sig.version != 1 )
      throw new DKIMSignature.Error( 'Unknown version' )

    if( sig.algorithm == null || !sig.algorithm.length )
      throw new DKIMSignature.Error( 'Missing algorithm' )
    if( sig.data == null || !sig.data.length )
      throw new DKIMSignature.Error( 'Missing data' )
    if( sig.bodyHash == null || !sig.bodyHash.length )
      throw new DKIMSignature.Error( 'Missing body hash' )
    if( sig.selector == null || !sig.selector.length )
      throw new DKIMSignature.Error( 'Missing selector' )
    if( sig.domain == null || !sig.domain.length )
      throw new DKIMSignature.Error( 'Missing domain' )
    if( sig.headers == null || !sig.headers.length )
      throw new DKIMSignature.Error( 'Missing headers' )

    return sig

  }

  /** @type {Boolean} Whether the signature has expired */
  get hasExpired() {
    if( this.expiresAt == null ) return false
    return this.expiresAt.getTime() >= Date.now()
  }

  /**
   * Create a JSON-serializable object of the signature
   * @returns {Object}
   */
  toJSON() {

    var value = {}

    value.version = this.version
    value.algorithm = this.algorithm
    value.data = this.data?.toString( 'base64' )
    value.bodyHash = this.bodyHash?.toString( 'base64' )
    value.bodyLength = this.bodyLength
    value.queryMethods = this.queryMethods.slice()
    value.canonicalization = this.canonicalization.slice()
    value.identifier = this.identifier
    value.selector = this.selector
    value.createdAt = this.createdAt?.toJSON()
    value.expiresAt = this.expiresAt?.toJSON()
    value.domain = this.domain
    value.headers = this.headers?.slice()
    value.copiedHeaders = this.copiedHeaders?.slice()
    value.unknownTags = this.unknownTags?.size
      ? Array.from( this.unknownTags.entries() )
      : undefined

    return value

  }

  /**
   * Serialize the signature to a string
   * @returns {String}
   */
  toString() {

    var tags = [
      `v=${ this.version }`,
      `a=${ this.algorithm ?? '' }`,
      `d=${ this.domain ? url.domainToASCII( this.domain ) : '' }`,
      `s=${ this.selector ? subdomainToASCII( this.selector ) : '' }`
    ]

    // Contract the canonicalization method (or omit if it's the default "simple/simple")
    if( Array.isArray( this.canonicalization ) ) {
      switch( true ) {
        case this.canonicalization[0] == 'simple' && this.canonicalization[1] == 'simple': break;
        case this.canonicalization[1] == 'simple': tags.push( `c=${this.canonicalization[0]}` ); break
        default: tags.push( `c=${this.canonicalization.join( '/' )}` ); break
      }
    }

    // Only add query methods if they're not the default
    if( this.queryMethods && !( this.queryMethods.length == 1 && this.queryMethods[0] == 'dns/txt' ))
      tags.push( `q=${ this.queryMethods.join( ':' ) }` )

    if( this.identifier ) tags.push( `i=${ quotedPrintable.encode( this.identifier ) }` )
    if( this.createdAt ) tags.push( `t=${ BigInt( this.createdAt.getTime() / 1000 ) }` )
    if( this.expiresAt ) tags.push( `x=${ BigInt( this.expiresAt.getTime() / 1000 ) }` )

    tags.push( `h=${ Array.isArray( this.headers ) ? this.headers.join( ':' ) : '' }` )

    if( this.copiedHeaders ) {
      let headers = this.copiedHeaders
        .map( header => quotedPrintable.encode( header ) )
        .join( '|' )
      tags.push( `z=${headers}` )
    }

    if( this.bodyLength != null ) tags.push( `l=${ this.bodyLength }` )

    tags.push( `bh=${ this.bodyHash != null ? this.bodyHash.toString( 'base64' ) : '' }` )
    tags.push( `b=${ this.data != null ? this.data.toString( 'base64' ) : '' }` )

    if( this.unknownTags != null && this.unknownTags.size ) {
      for( let [ tagName, tagValue ] of this.unknownTags ) {
        tags.push( `${tagName}=${tagValue}` )
      }
    }

    return tags.join( '; ' )

  }

}

module.exports = DKIMSignature
