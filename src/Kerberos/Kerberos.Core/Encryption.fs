namespace Kerberos.Core

open System.Collections.Immutable
open Kerberos.Domain

module internal Encryption =
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

    let cryptASResponseAttribute (attr: ASResponseAttribute) (key: string) (crypt): ASResponseAttribute =
        let crypt str = crypt str key
        let tgsId = crypt attr.tgsId
        let timestamp = crypt attr.timestamp
        let lifetime = crypt attr.lifetime
        let tgsSessionKey = crypt attr.tgsSessionKey

        { tgsId = tgsId
          timestamp = timestamp
          lifetime = lifetime
          tgsSessionKey = tgsSessionKey }

    let cryptUserAuthenticator (userAuth: UserAuthenticator) (key: string) (crypt): UserAuthenticator =
        let crypt str = crypt str key
        let userId = crypt userAuth.userId
        let timestamp = crypt userAuth.timestamp

        { userId = userId
          timestamp = timestamp }

    let cryptTGSResponseAttribute (attr: TGSResponseAttribute) (key: string) (crypt): TGSResponseAttribute =
        let crypt str = crypt str key
        let serviceId = crypt attr.serviceId
        let timestamp = crypt attr.timestamp
        let lifetime = crypt attr.lifetime
        let serviceSessionKey = crypt attr.serviceSessionKey

        { serviceId = serviceId
          timestamp = timestamp
          lifetime = lifetime
          serviceSessionKey = serviceSessionKey }

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

    let cryptServiceAttribute (attr: ServiceAttribute) (key: string) (crypt): ServiceAttribute =
        let crypt str = crypt str key
        let serviceId = crypt attr.serviceId
        let timestamp = crypt attr.timestamp

        { serviceId = serviceId
          timestamp = timestamp }