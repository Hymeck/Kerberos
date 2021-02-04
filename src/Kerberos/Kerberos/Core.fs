namespace Kerberos

open Domain
open DES.Utils

module Core =
    let private cryptAsResponseAttribute (attr: ASResponseAttribute) (key: string) (crypt): ASResponseAttribute =
        let tgsId = crypt attr.tgsId key
        let tgsSessionKey = crypt attr.tgsSessionKey key

        { attr with
              tgsId = tgsId
              tgsSessionKey = tgsSessionKey }

    let private cryptTgt (tgt: TicketGrantingTicket) (key: string) (crypt): TicketGrantingTicket =
        let tgsId = crypt tgt.tgsId key
        let userId = crypt tgt.userId key
        let tgsSessionKey = crypt tgt.tgsSessionKey key

        { tgt with
              tgsId = tgsId
              userId = userId
              tgsSessionKey = tgsSessionKey }

    let encryptTgt (tgt: TicketGrantingTicket) (key: string) = cryptTgt tgt key fullEncrypt

    let decryptTgt (tgt: TicketGrantingTicket) (key: string) = cryptTgt tgt key fullDecrypt

    let encryptAsResponseAttribute (attr: ASResponseAttribute) (key: string) =
        cryptAsResponseAttribute attr key fullEncrypt

    let decryptAsResponseAttribute (attr: ASResponseAttribute) (key: string) =
        cryptAsResponseAttribute attr key fullDecrypt

    let encryptASResponse (asResponse: ASResponse) (clientSecretKey: string) (tgsSecretKey: string): ASResponse =
        // todo: encrypt AS response attribute with client secret key
        let attribute =
            encryptAsResponseAttribute asResponse.attribute clientSecretKey
        // todo: encrypt tgt with TGS secret key
        let tgt = encryptTgt asResponse.tgt tgsSecretKey
        { attribute = attribute; tgt = tgt }

    let encryptTGSRequest (tgsRequest: TGSRequest) (tgsSessionKey: string): TGSRequest =
        // todo: encrypt user authenticator with TGS session key
        { tgt = tgsRequest.tgt
          attribute = tgsRequest.attribute
          userAuthenticator = tgsRequest.userAuthenticator }

    let encryptTGSResponse (tgsResponse: TGSResponse) (tgsSessionKey: string) (serviceSecretKey: string): TGSResponse =
        // todo: encrypt TGS response attribute with TGS session key
        // todo: encrypt service ticket with service secret key
        { attribute = tgsResponse.attribute
          serviceTicket = tgsResponse.serviceTicket }

    let encryptServiceRequest (serviceRequest: ServiceRequest) (serviceSessionKey: string): ServiceRequest =
        // todo: encrypt user authenticator with service session key
        { serviceTicket = serviceRequest.serviceTicket
          userAuthenticator = serviceRequest.userAuthenticator }

    let encryptServiceResponse (serviceResponse: ServiceResponse) (serviceSessionKey: string): ServiceResponse =
        // todo: encrypt service attribute
        { attribute = serviceResponse.attribute }