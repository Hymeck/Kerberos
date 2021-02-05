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
    
    let decodeASResponseAttribute (asResponse: ASResponse) (userSecretKey: string): ASResponseAttribute =
        decryptASResponseAttribute asResponse.attribute userSecretKey