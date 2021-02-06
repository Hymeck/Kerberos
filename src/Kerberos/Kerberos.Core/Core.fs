namespace Kerberos.Core

open Kerberos.Domain
open DES.DESMethods
open Encryption

module Core =

    let encryptASResponse (asResponse: ASResponse) (clientSecretKey: string) (tgsSecretKey: string): ASResponse =
        let attribute =
            cryptASResponseAttribute asResponse.attribute clientSecretKey encrypt

        let tgt =
            cryptTGT asResponse.tgt tgsSecretKey encrypt

        { attribute = attribute; tgt = tgt }

    let encryptTGSRequest (tgsRequest: TGSRequest) (tgsSessionKey: string): TGSRequest =
        let userAuth =
            cryptUserAuthenticator tgsRequest.userAuthenticator tgsSessionKey encrypt

        { tgt = tgsRequest.tgt
          attribute = tgsRequest.attribute
          userAuthenticator = userAuth }

    let encryptTGSResponse (tgsResponse: TGSResponse) (tgsSessionKey: string) (serviceSecretKey: string): TGSResponse =
        let attribute =
            cryptTGSResponseAttribute tgsResponse.attribute tgsSessionKey encrypt

        let ticket =
            cryptServiceTicket tgsResponse.serviceTicket serviceSecretKey encrypt

        { attribute = attribute
          serviceTicket = ticket }

    let encryptServiceRequest (serviceRequest: ServiceRequest) (serviceSessionKey: string): ServiceRequest =
        let userAuth =
            cryptUserAuthenticator serviceRequest.userAuthenticator serviceSessionKey encrypt

        { serviceTicket = serviceRequest.serviceTicket
          userAuthenticator = userAuth }

    let encryptServiceResponse (serviceResponse: ServiceResponse) (serviceSessionKey: string): ServiceResponse =
        let attr =
            cryptServiceAttribute serviceResponse.attribute serviceSessionKey encrypt

        { attribute = attr }

    let decryptASResponseAttribute (attr: ASResponseAttribute) (userSecretKey: string): ASResponseAttribute =
        cryptASResponseAttribute attr userSecretKey decrypt

    let decryptTGSResponseAttribute (attr: TGSResponseAttribute) (tgsSessionKey: string): TGSResponseAttribute =
        cryptTGSResponseAttribute attr tgsSessionKey decrypt

    let decryptServiceResponse (attr: ServiceAttribute) (serviceSessionKey: string): ServiceAttribute =
        cryptServiceAttribute attr serviceSessionKey decrypt