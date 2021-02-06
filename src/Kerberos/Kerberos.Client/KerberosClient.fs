namespace Kerberos.Client

open System
open System.Net
open Kerberos.Domain
open Kerberos.Server.KerberosServer
open Kerberos.Core.Core

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
    
    let sendASRequest (request: ASRequest): Option<ASResponse> =
        sendASResponse (request)
    
    let decodeASResponse (response: ASResponse) (userSecretKey: string): ASResponseAttribute =
        decryptASResponseAttribute response.attribute userSecretKey
    
    // tgt, serviceId, ticketLifetime, userId, tgsSessionKey
    let createTGSRequest (tgt: TicketGrantingTicket) (serviceId: string) (ticketLifetime: TimeSpan) (userId: string) (tgsSessionKey: string): TGSRequest =
        let attr = {serviceId = serviceId; ticketLifetime = ticketLifetime.Ticks.ToString()}
        let timestamp = DateTimeOffset.Now.Ticks.ToString()
        let userAuth = {userId = userId; timestamp = timestamp}
        let request = {tgt = tgt; attribute = attr; userAuthenticator = userAuth}
        encryptTGSRequest request tgsSessionKey
        
        
    
    let sendTGSRequest (request: TGSRequest): Option<TGSResponse> =
        sendTGSResponse request