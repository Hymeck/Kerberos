namespace Kerberos.Shared

open Kerberos.Domain

module Encryption =
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

    let cryptServiceAttribute (attr: ServiceAttribute) (key: string) (crypt): ServiceAttribute =
        let crypt str = crypt str key
        let serviceId = crypt attr.serviceId
        let timestamp = crypt attr.timestamp

        { serviceId = serviceId
          timestamp = timestamp }