namespace Kerberos.Client

open System
open System.Net
open Kerberos.Domain
open Kerberos.Server.KerberosServer
open Kerberos.Shared.Encryption
open DES.DESMethods

module KerberosClient =

    type UserData =
        { userId: string
          serviceId: string
          ip: IPAddress
          tgtLifetime: TimeSpan }

    let createASRequest (data: UserData): ASRequest =
        { userId = data.userId
          serviceId = data.serviceId
          ipAddress = data.ip.ToString()
          tgtLifetime = data.tgtLifetime.Ticks.ToString() }

    let sendASRequest (request: ASRequest): Option<ASResponse> = sendASResponse (request)

    let decryptASResponse (response: ASResponse) (userSecretKey: string): ASResponseAttribute =
        cryptASResponseAttribute response.attribute userSecretKey decrypt

    let private encryptTGSRequest (tgsRequest: TGSRequest) (tgsSessionKey: string): TGSRequest =
        let userAuth =
            cryptUserAuthenticator tgsRequest.userAuthenticator tgsSessionKey encrypt

        { tgt = tgsRequest.tgt
          attribute = tgsRequest.attribute
          userAuthenticator = userAuth }

    let createTGSRequest (tgt: TicketGrantingTicket)
                         (serviceId: string)
                         (ticketLifetime: TimeSpan)
                         (userId: string)
                         (tgsSessionKey: string)
                         : TGSRequest =
        let attr =
            { serviceId = serviceId
              ticketLifetime = ticketLifetime.Ticks.ToString() }

        let timestamp = DateTimeOffset.Now.Ticks.ToString()

        let userAuth =
            { userId = userId
              timestamp = timestamp }

        let request =
            { tgt = tgt
              attribute = attr
              userAuthenticator = userAuth }

        encryptTGSRequest request tgsSessionKey

    let sendTGSRequest (request: TGSRequest): Option<TGSResponse> = sendTGSResponse request

    let decryptTGSResponse (response: TGSResponse) (tgsSessionKey: string): TGSResponseAttribute =
        cryptTGSResponseAttribute response.attribute tgsSessionKey decrypt

    let private encryptServiceRequest (serviceRequest: ServiceRequest) (serviceSessionKey: string): ServiceRequest =
        let userAuth =
            cryptUserAuthenticator serviceRequest.userAuthenticator serviceSessionKey encrypt

        { serviceTicket = serviceRequest.serviceTicket
          userAuthenticator = userAuth }

    let createServiceRequest (ticket: ServiceTicket) (userId: string) (serviceSessionKey: string): ServiceRequest =
        let userAuth =
            { userId = userId
              timestamp = DateTime.Now.Ticks.ToString() }

        let request =
            { serviceTicket = ticket
              userAuthenticator = userAuth }

        encryptServiceRequest request serviceSessionKey

    let sendServiceRequest (request: ServiceRequest) (serviceId: string): Option<ServiceResponse> =
        sendServiceResponse request serviceId

    let decryptServiceResponse (response: ServiceResponse) (serviceSessionKey: string): ServiceAttribute =
        cryptServiceAttribute response.attribute serviceSessionKey decrypt