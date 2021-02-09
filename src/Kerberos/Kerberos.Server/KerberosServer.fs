namespace Kerberos.Server

open System
open System.Collections.Generic
open System.Collections.Immutable
open Kerberos.Domain
open Kerberos.Shared.Encryption
open DES.DESMethods

module KerberosServer =
    let userDictionary =
        let users = Dictionary<string, string>()
        users.Add("poet", "Q_ObPm0l")
        users.Add("punk", "[aObL_+p")
        users.Add("drocher", "NaOuL_Jg")
        users.ToImmutableDictionary()

    let tgsId = "aPxlOvrnj10-"

    let generateTgsSessionKey =
        Guid.NewGuid().ToString().Substring(0, 8)

    let cryptTGT (tgt: TicketGrantingTicket) (key: string) (crypt): TicketGrantingTicket =
        let crypt str = crypt str key
        let userId = crypt tgt.userId
        let tgsId = crypt tgt.tgsId
        let timestamp = crypt tgt.timestamp

        let ipAddress =
            ImmutableList.ToImmutableList(Seq.map crypt tgt.userIpAddress)

        let lifetime = crypt tgt.lifetime
        let tgsSessionKey = crypt tgt.tgsSessionKey

        { userId = userId
          tgsId = tgsId
          timestamp = timestamp
          userIpAddress = ipAddress
          lifetime = lifetime
          tgsSessionKey = tgsSessionKey }

    let encryptASResponse (asResponse: ASResponse) (clientSecretKey: string) (tgsSecretKey: string): ASResponse =
        let attribute =
            cryptASResponseAttribute asResponse.attribute clientSecretKey encrypt

        let tgt =
            cryptTGT asResponse.tgt tgsSecretKey encrypt

        { attribute = attribute; tgt = tgt }

    let tgsSecretKey = "zi#gml+l"

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

    let encryptServiceResponse (serviceResponse: ServiceResponse) (serviceSessionKey: string): ServiceResponse =
        let attr =
            cryptServiceAttribute serviceResponse.attribute serviceSessionKey encrypt

        { attribute = attr }

    let generateServiceSessionKey =
        Guid.NewGuid().ToString().Substring(0, 8)

    let serviceDictionary =
        let services = Dictionary<string, string>()
        services.Add("poetarium", "xnqM<-=t")
        services.Add("punktionary", "aPb076_!")
        services.Add("drochium", "gvIx-_aq")
        services.ToImmutableDictionary()

    let compareTGSRequestInfo (tgt: TicketGrantingTicket) (userAuth: UserAuthenticator): bool =
        tgt.userId = userAuth.userId

    let cryptServiceTicket (st: ServiceTicket) (key: string) (crypt): ServiceTicket =
        let crypt str = crypt str key
        let userId = crypt st.userId
        let serviceId = crypt st.serviceId
        let timestamp = crypt st.timestamp

        let ipAddress =
            ImmutableList.ToImmutableList(Seq.map crypt st.userIpAddress)

        let serviceTicketLifetime = crypt st.serviceTicketLifetime
        let serviceSessionKey = crypt st.serviceSessionKey

        { userId = userId
          serviceId = serviceId
          timestamp = timestamp
          userIpAddress = ipAddress
          serviceTicketLifetime = serviceTicketLifetime
          serviceSessionKey = serviceSessionKey }

    let encryptTGSResponse (tgsResponse: TGSResponse) (tgsSessionKey: string) (serviceSecretKey: string): TGSResponse =
        let attribute =
            cryptTGSResponseAttribute tgsResponse.attribute tgsSessionKey encrypt

        let ticket =
            cryptServiceTicket tgsResponse.serviceTicket serviceSecretKey encrypt

        { attribute = attribute
          serviceTicket = ticket }

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

    let sendServiceResponse (request: ServiceRequest) (serviceId: string): Option<ServiceResponse> =
        let services = serviceDictionary
        let serviceSecretKey = services.[serviceId]

        let ticket =
            cryptServiceTicket request.serviceTicket serviceSecretKey decrypt

        let serviceSessionKey = ticket.serviceSessionKey
        let serviceId = ticket.serviceId
        let timestamp = DateTime.Now.Ticks.ToString()

        let attribute =
            { serviceId = serviceId
              timestamp = timestamp }

        let response = { attribute = attribute }
        Some(encryptServiceResponse response serviceSessionKey)