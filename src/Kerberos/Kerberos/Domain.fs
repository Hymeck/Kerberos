namespace Kerberos

open System
open System.Collections.Immutable
open System.Net

module Domain =
    type ASRequest =
        { userId: string
          serviceId: string
          ipAddress: IPAddress
          tgtLifetime: TimeSpan }

    type TicketGrantingTicket =
        { userId: string
          tgsId: string
          timestamp: DateTimeOffset
          userIpAddress: ImmutableList<IPAddress>
          lifetime: TimeSpan
          tgsSessionKey: string }

    type ASResponseAttribute =
        { tgsId: string
          timestamp: DateTimeOffset
          lifetime: TimeSpan (* same as TGT lifetime *)
          tgsSessionKey: string }

    type ASResponse =
        { attribute: ASResponseAttribute (* encrypt with client secret key *)
          tgt: TicketGrantingTicket (* encrypt with TGS secret key *)  }

    type TGSRequestAttribute =
        { serviceId: string
          ticketLifetime: TimeSpan }

    type UserAuthenticator = { userId: string; timestamp: DateTimeOffset }

    type TGSRequest =
        { tgt: TicketGrantingTicket (* was encrypted with TGS secret key *)
          attribute: TGSRequestAttribute
          userAuthenticator: UserAuthenticator (* encrypt with TGS session key *)  }

    type TGSResponseAttribute =
        { serviceId: string
          timestamp: DateTimeOffset
          lifetime: TimeSpan
          serviceSessionKey: string }

    type ServiceTicket =
        { userId: string
          serviceId: string
          timestamp: DateTimeOffset
          userIpAddress: ImmutableList<IPAddress>
          serviceTicketLifetime: TimeSpan
          serviceSessionKey: string }

    type TGSResponse =
        { attribute: TGSResponseAttribute (* encrypt with TGS session key *)
          serviceTicket: ServiceTicket (* encrypt with service secret key *)  }

    type ServiceRequest =
        { serviceTicket: ServiceTicket (* was encrypted with service secret key *)
          userAuthenticator: UserAuthenticator (* encrypt with service session key *)  }

    type ServiceAttribute =
        { serviceId: string
          timestamp: DateTimeOffset }

    type ServiceResponse =
        { attribute: ServiceAttribute (* encrypt with service session key *)  } 