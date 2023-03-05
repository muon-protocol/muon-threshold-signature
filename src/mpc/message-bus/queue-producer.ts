import BaseMessageQueue from './base-message-queue.js'
import TimeoutPromise from './timeout-promise.js'
import NodeCache from 'node-cache'

const callCache = new NodeCache({
  stdTTL: 15*60, // Keep call in memory for 15 minutes
  useClones: false,
});

export type CallOptions = {
  /**
   * If response not receive after this timeout, call result will reject.
   */
  timeout?: number,
  /**
   * Define error message for timeout promise rejection.
   */
  timeoutMessage?: string,
  /**
   * Define cluster PID to running ipc method.
   * If defined, call will forward to specified core cluster process.
   */
  pid?: number
}

type CacheContent<T> = {
  message: T,
  options: CallOptions,
  promise: TimeoutPromise
}

export default class QueueProducer<MessageType> extends BaseMessageQueue {

  constructor(busName: string){
    super(busName)

    this.receiveRedis.subscribe(this.getProcessResponseChannel());
    this.receiveRedis.on("message", this.onResponseReceived.bind(this));
  }

  /**
   * @param event
   * @param options
   * @param options.timeout
   * @param options.timeoutMessage
   * @param options.await - wait to end the event process and then run new one.
   * @returns {Promise<Object>}
   */
  send(message: MessageType, options: CallOptions={}){
    options = {
      timeout: 0,
      timeoutMessage: "Queue request timeout!",
      pid: -1,
      ...(!!options ? options : {})
    };

    let wMsg = this.wrapData(message)
    let promise = new TimeoutPromise(options.timeout, options.timeoutMessage)
    // this._calls[callId] = remoteResult;
    const content: CacheContent<MessageType> = {
      message,
      options,
      promise
    }
    callCache.set(wMsg.uid, content);
    if(options.pid && options.pid > -1)
      this.sendRedis.lpush(`${this.channelName}@${options.pid}`, JSON.stringify(wMsg));
    else
      this.sendRedis.lpush(this.channelName, JSON.stringify(wMsg));
    return promise.promise;
  }

  async onResponseReceived(channel: string, strMessage: string) {
    const rawResponse = JSON.parse(strMessage);
    let {pid, uid, data: {error=undefined, response=undefined}} = rawResponse;
    let content:CacheContent<MessageType> = callCache.get(uid)!;
    if(content) {
      if (!error) {
        content.promise.resolve(response)
      }
      else {
        console.error(
          `${this.ConstructorName}[${this.busName}] result contains error`,
          {
            message: content.message,
            rawResponse
          },
        );
        content.promise.reject({...error, onRemoteSide: true})
      }
    }
    else{
      console.error(`${this.ConstructorName}[${this.busName}] Result promise not found: `, rawResponse);
      // TODO: what to do? it may timed out.
    }
  }

  get ConstructorName() {
    let superClass = Object.getPrototypeOf(this);
    return superClass.constructor.name
  }
}
