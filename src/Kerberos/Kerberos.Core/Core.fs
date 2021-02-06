namespace Kerberos.Core

open Kerberos.Domain
open Encryption
open DES.DESMethods

module Core =

    let encryptASResponse (asResponse: ASResponse) (clientSecretKey: string) (tgsSecretKey: string): ASResponse =
        let attribute =
            cryptASResponseAttribute asResponse.attribute clientSecretKey encrypt

        let tgt =
            cryptTGT asResponse.tgt tgsSecretKey encrypt

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

    let decryptASResponseAttribute (attr: ASResponseAttribute) (userSecretKey: string): ASResponseAttribute =
        cryptASResponseAttribute attr userSecretKey decrypt