﻿namespace Kerberos.Domain

open System.Collections.Immutable

type ASRequest =
    { userId: string
      serviceId: string
      ipAddress: string
      tgtLifetime: string }

type TicketGrantingTicket =
    { userId: string
      tgsId: string
      timestamp: string
      userIpAddress: ImmutableList<string>
      lifetime: string
      tgsSessionKey: string }

type ASResponseAttribute =
    { tgsId: string
      timestamp: string
      lifetime: string (* same as TGT lifetime *)
      tgsSessionKey: string }

type ASResponse =
    { attribute: ASResponseAttribute (* encrypt with client secret key *)
      tgt: TicketGrantingTicket (* encrypt with TGS secret key *)  }

type TGSRequestAttribute =
    { serviceId: string
      ticketLifetime: string }

type UserAuthenticator = { userId: string; timestamp: string }

type TGSRequest =
    { tgt: TicketGrantingTicket (* was encrypted with TGS secret key *)
      attribute: TGSRequestAttribute
      userAuthenticator: UserAuthenticator (* encrypt with TGS session key *)  }

type TGSResponseAttribute =
    { serviceId: string
      timestamp: string
      lifetime: string
      serviceSessionKey: string }

type ServiceTicket =
    { userId: string
      serviceId: string
      timestamp: string
      userIpAddress: ImmutableList<string>
      serviceTicketLifetime: string
      serviceSessionKey: string }

type TGSResponse =
    { attribute: TGSResponseAttribute (* encrypt with TGS session key *)
      serviceTicket: ServiceTicket (* encrypt with service secret key *)  }

type ServiceRequest =
    { serviceTicket: ServiceTicket (* was encrypted with service secret key *)
      userAuthenticator: UserAuthenticator (* encrypt with service session key *)  }

type ServiceAttribute =
    { serviceId: string
      timestamp: string }

type ServiceResponse =
    { attribute: ServiceAttribute (* encrypt with service session key *)  }     