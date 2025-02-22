/**
 * Socket implementation that uses flash SocketPool class as a backend.
 *
 * @author Dave Longley
 * @author Chris Breuer
 */

/// <reference lib="dom" />

import { decode64, encode64 } from './utils'

interface Socket {
  id: string
  connected: (e: SocketEvent) => void
  closed: (e: SocketEvent) => void
  data: (e: SocketEvent) => void
  error: (e: SocketEvent) => void
  destroy: () => void
  connect: (options: ConnectOptions) => void
  close: () => void
  isConnected: () => boolean
  send: (bytes: string) => boolean
  receive: (count: number) => string | null
  bytesAvailable: () => number
}

interface SocketEvent {
  id: string
  type: string
  bytesAvailable?: number
}

interface ConnectOptions {
  host: string
  port: number
  policyPort?: number
  policyUrl?: string
}

interface FlashApi {
  init: (options: { marshallExceptions: boolean }) => void
  cleanup: () => void
  subscribe: (event: string, handler: string) => void
  create: () => string
  destroy: (id: string) => void
  connect: (id: string, host: string, port: number, policyPort: number, policyUrl: string | null) => void
  close: (id: string) => void
  isConnected: (id: string) => boolean
  send: (id: string, data: string) => boolean
  receive: (id: string, count: number) => { rval: string | null }
  getBytesAvailable: (id: string) => number
}

interface SocketPool {
  id: string
  flashApi: FlashApi
  sockets: { [key: string]: Socket }
  policyPort: number
  policyUrl: string | null
  handler: (e: SocketEvent) => void
  destroy: () => void
  createSocket: (options: SocketOptions) => Socket
}

interface SocketOptions {
  connected?: (e: SocketEvent) => void
  closed?: (e: SocketEvent) => void
  data?: (e: SocketEvent) => void
  error?: (e: SocketEvent) => void
}

export const net = {
  socketPools: {} as { [key: string]: SocketPool },
}

/**
 * Creates a flash socket pool.
 *
 * @param options:
 *          flashId: the dom ID for the flash object element.
 *          policyPort: the default policy port for sockets, 0 to use the flash default.
 *          policyUrl: the default policy file URL for sockets (if provided used instead of a policy port).
 *          msie: true if the browser is msie, false if not.
 *
 * @return the created socket pool.
 */
export function createSocketPool(options: {
  flashId: string
  policyPort?: number
  policyUrl?: string
  msie?: boolean
}): SocketPool {
  // set default
  options.msie = options.msie || false

  // initialize the flash interface
  const spId = options.flashId
  const element = document.getElementById(spId)
  if (!element) {
    throw new Error(`Flash element with ID ${spId} not found`)
  }
  const api = element as unknown as FlashApi
  api.init({ marshallExceptions: !options.msie })

  // create socket pool entry
  const sp: SocketPool = {
    // ID of the socket pool
    id: spId,
    // flash interface
    flashApi: api,
    // map of socket ID to sockets
    sockets: {},
    // default policy port
    policyPort: options.policyPort || 0,
    // default policy URL
    policyUrl: options.policyUrl || null,
    // handler function will be set below
    handler: (e: SocketEvent) => {},
    // destroy function
    destroy: () => {
      delete net.socketPools[options.flashId]
      for (const id in sp.sockets) {
        sp.sockets[id].destroy()
      }
      sp.sockets = {}
      api.cleanup()
    },
    // createSocket function
    createSocket: (options: SocketOptions) => {
      return createSocket({ ...options, flashId: spId })
    },
  }

  // create event handler, subscribe to flash events
  if (options.msie === true) {
    sp.handler = function (e: SocketEvent) {
      if (e.id in sp.sockets) {
        // get handler function
        let f: keyof Socket
        switch (e.type) {
          case 'connect':
            f = 'connected'
            break
          case 'close':
            f = 'closed'
            break
          case 'socketData':
            f = 'data'
            break
          default:
            f = 'error'
            break
        }
        /* IE calls javascript on the thread of the external object
          that triggered the event (in this case flash) ... which will
          either run concurrently with other javascript or pre-empt any
          running javascript in the middle of its execution (BAD!) ...
          calling setTimeout() will schedule the javascript to run on
          the javascript thread and solve this EVIL problem. */
        setTimeout(() => { sp.sockets[e.id][f](e) }, 0)
      }
    }
  }
  else {
    sp.handler = function (e: SocketEvent) {
      if (e.id in sp.sockets) {
        // get handler function
        let f: keyof Socket
        switch (e.type) {
          case 'connect':
            f = 'connected'
            break
          case 'close':
            f = 'closed'
            break
          case 'socketData':
            f = 'data'
            break
          default:
            f = 'error'
            break
        }
        sp.sockets[e.id][f](e)
      }
    }
  }

  // store socket pool
  net.socketPools[spId] = sp

  const handler = `forge.net.socketPools['${spId}'].handler`
  api.subscribe('connect', handler)
  api.subscribe('close', handler)
  api.subscribe('socketData', handler)
  api.subscribe('ioError', handler)
  api.subscribe('securityError', handler)

  return sp
}

/**
 * Destroys a flash socket pool.
 *
 * @param options:
 *          flashId: the dom ID for the flash object element.
 */
function destroySocketPool(options: any) {
  if (options.flashId in net.socketPools) {
    const sp = net.socketPools[options.flashId]
    sp.destroy()
  }
}

/**
 * Creates a new socket.
 *
 * @param options:
 *          flashId: the dom ID for the flash object element.
 *          connected: function(event) called when the socket connects.
 *          closed: function(event) called when the socket closes.
 *          data: function(event) called when socket data has arrived,
 *            it can be read from the socket using receive().
 *          error: function(event) called when a socket error occurs.
 *
 * @return the created socket.
 */
export function createSocket(options: SocketOptions & { flashId: string }): Socket {
  if (!(options.flashId in net.socketPools)) {
    throw new Error(`Socket pool with ID ${options.flashId} not found`)
  }

  // get related socket pool
  const sp = net.socketPools[options.flashId]
  const api = sp.flashApi

  // create flash socket
  const id = api.create()

  // create javascript socket wrapper
  const socket: Socket = {
    id,
    // set handlers
    connected: options.connected || function (e: SocketEvent) {},
    closed: options.closed || function (e: SocketEvent) {},
    data: options.data || function (e: SocketEvent) {},
    error: options.error || function (e: SocketEvent) {},
    destroy() {
      api.destroy(id)
      delete sp.sockets[id]
    },
    connect(options: ConnectOptions) {
      // give precedence to policy URL over policy port
      // if no policy URL and passed port isn't 0, use default port,
      // otherwise use 0 for the port
      const policyUrl = options.policyUrl || null
      let policyPort = 0
      if (policyUrl === null && options.policyPort !== 0) {
        policyPort = options.policyPort || sp.policyPort
      }
      api.connect(id, options.host, options.port, policyPort, policyUrl)
    },
    close() {
      api.close(id)
      this.closed({
        id: this.id,
        type: 'close',
        bytesAvailable: 0,
      })
    },
    isConnected() {
      return api.isConnected(id)
    },
    send(bytes: string) {
      return api.send(id, encode64(bytes))
    },
    receive(count: number) {
      const rval = api.receive(id, count).rval
      return (rval === null) ? null : decode64(rval)
    },
    bytesAvailable() {
      return api.getBytesAvailable(id)
    },
  }

  // store and return socket
  sp.sockets[id] = socket
  return socket
}

export default net
