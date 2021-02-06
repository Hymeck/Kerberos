namespace Kerberos.Server

open System
open System.Collections.Generic
open System.Collections.Immutable
open Kerberos.Domain
open Kerberos.Core.Core
open Kerberos.Core.Encryption
open DES.DESMethods

module KerberosServer =
    let tgsId = "aPxlOvrnj10-"
    let tgsSecretKey = "zi#gml+l"

    let generateTgsSessionKey =
        Guid.NewGuid().ToString().Substring(0, 8)

    let generateServiceSessionKey =
        Guid.NewGuid().ToString().Substring(0, 8)

    let userDictionary =
        let users = Dictionary<string, string>()
        users.Add("poet", "Q_ObPm0l")
        users.Add("punk", "[aObL_+p")
        users.Add("drocher", "NaOuL_Jg")
        users

    let serviceDictionary =
        let services = Dictionary<string, string>()
        services.Add("poetarium", "xnqM<-=t")
        services.Add("punktionary", "aPb076_!")
        services.Add("drochium", "gvIx-_aq")
        services
        

    let sendASResponse (request: ASRequest): Option<ASResponse> =
        let users = userDictionary

        if not (users.ContainsKey request.userId) then
            None
        else
            let tgsId = tgsId
            let timestamp = DateTime.Now.Ticks.ToString()

            let lifetime =
                (TimeSpan.FromSeconds(float 30)).Ticks.ToString()

            let tgsSessionKey = generateTgsSessionKey

            let tgt =
                { userId = request.userId
                  tgsId = tgsId
                  timestamp = timestamp
                  userIpAddress = ImmutableList.Create(request.ipAddress)
                  lifetime = lifetime
                  tgsSessionKey = tgsSessionKey }

            let attribute =
                { tgsId = tgsId
                  timestamp = timestamp
                  lifetime = lifetime
                  tgsSessionKey = tgsSessionKey }

            let response = { attribute = attribute; tgt = tgt }
            Some(encryptASResponse response (users.[request.userId]) (tgsSecretKey))

    let compareTGSRequestInfo (tgt: TicketGrantingTicket) (userAuth: UserAuthenticator): bool =
        tgt.userId = userAuth.userId

    let sendTGSResponse (request: TGSRequest): Option<TGSResponse> =
        let services = serviceDictionary

        if not (services.ContainsKey request.attribute.serviceId) then
            None
        else
            let tgsSecretKey = tgsSecretKey

            let tgt =
                cryptTGT request.tgt tgsSecretKey decrypt

            let userAuth =
                cryptUserAuthenticator request.userAuthenticator tgt.tgsSessionKey decrypt

            if (compareTGSRequestInfo tgt userAuth) = false then
                None
            else
                let serviceId = request.attribute.serviceId
                let timestamp = DateTime.Now.Ticks.ToString()
                let lifetime = tgt.lifetime
                let serviceSessionKey = generateServiceSessionKey

                let attr =
                    { serviceId = serviceId
                      timestamp = timestamp
                      lifetime = lifetime
                      serviceSessionKey = serviceSessionKey }

                let serviceTicket =
                    { userId = userAuth.userId
                      serviceId = serviceId
                      timestamp = timestamp
                      userIpAddress = tgt.userIpAddress
                      serviceTicketLifetime = (TimeSpan.FromSeconds(float 20).Ticks.ToString())
                      serviceSessionKey = serviceSessionKey }

                let response =
                    { attribute = attr
                      serviceTicket = serviceTicket }

                Some(encryptTGSResponse response tgt.tgsSessionKey services.[serviceId])

    let sendServiceResponse (request: ServiceRequest): Option<ServiceResponse> =
        //todo: remove hardcode
        let serviceSecretKey = "aPb076_!"

        let ticket =
            cryptServiceTicket request.serviceTicket serviceSecretKey decrypt

        let serviceSessionKey = ticket.serviceSessionKey
        // todo: compare data
        let serviceId = ticket.serviceId
        let timestamp = DateTime.Now.Ticks.ToString()

        let attribute =
            { serviceId = serviceId
              timestamp = timestamp }

        let response = { attribute = attribute }
        Some(encryptServiceResponse response serviceSessionKey)