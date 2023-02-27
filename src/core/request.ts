import { defaultsDeep, inRange, random } from 'lodash';
import { createHmac } from 'crypto';
import { Subject } from 'rxjs';
import { AttemptOptions, retry } from '@lifeomic/attempt';
//import * as request from 'request-promise';
import { proxies } from 'http2-wrapper';
import got, { Agents, Options as OptionsInit } from 'got';
import { Options, Response } from 'request';
import { IgApiClient } from './client';
import {
  IgActionSpamError,
  IgCheckpointError,
  IgClientError,
  IgInactiveUserError,
  IgLoginRequiredError,
  IgNetworkError,
  IgNotFoundError,
  IgPrivateUserError,
  IgResponseError,
  IgSentryBlockError,
  IgUserHasLoggedOutError,
} from '../errors';
import { IgResponse } from '../types';
import JSONbigInt = require('json-bigint');

const JSONbigString = JSONbigInt({ storeAsString: true });

import debug from 'debug';
import { URL } from 'url';
import { OptionsWithUrl } from 'request-promise';

type Payload = { [key: string]: any } | string;

interface SignedPost {
  signed_body: string;
  ig_sig_key_version: string;
}

export class Request {
  private static requestDebug = debug('ig:request');
  end$ = new Subject();
  error$ = new Subject<IgClientError>();
  attemptOptions: Partial<AttemptOptions<any>> = {
    maxAttempts: 1,
  };
  defaults: Partial<Options> = {};

  constructor(private client: IgApiClient) {}

  private static requestTransform(body, response: Response, resolveWithFullResponse) {
    try {
      // Sometimes we have numbers greater than Number.MAX_SAFE_INTEGER in json response
      // To handle it we just wrap numbers with length > 15 it double quotes to get strings instead
      response.body = JSONbigString.parse(body);
    } catch (e) {
      if (inRange(response.statusCode, 200, 299)) {
        throw e;
      }
    }
    return resolveWithFullResponse ? response : response.body;
  }

  public async send<T = any>(userOptions: OptionsWithUrl, onlyCheckHttpStatus?: boolean): Promise<IgResponse<T>> {
    const baseUrl = 'https://i.instagram.com';
    if (!userOptions.url.toString().startsWith(baseUrl)) {
      userOptions.url = `https://i.instagram.com${userOptions.url}`;
    }

    let agents: Agents;
    const proxy = this.client.state.proxyUrl;
    if (proxy) {
      const http2Proxy = {
        proxyOptions: {
          url: new URL(proxy),
          rejectUnauthorized: false,
        },
      };
      const agent = new proxies.Http2OverHttp(http2Proxy);
      agents = { http2: agent };
    }
    const requestOptions: OptionsInit = {
      resolveBodyOnly: false,
      responseType: 'json',
      agent: agents,
      headers: this.getDefaultHeaders(),
      method: 'GET',
      http2: true,
    };
    const options = defaultsDeep(
      userOptions,
      {
        ...requestOptions,
        paginate: { transform: Request.requestTransform },
        cookieJar: this.client.state.cookieJar,
      },
      this.defaults,
    );
    Request.requestDebug(`Requesting ${options.method} ${options.url || options.uri || '[could not find url]'}`);
    const response = await this.faultTolerantRequest(options);
    this.updateState(response);
    process.nextTick(() => this.end$.next());
    if (response.body.status === 'ok' || (onlyCheckHttpStatus && response.statusCode === 200)) {
      return response;
    }
    const error = this.handleResponseError(response);
    process.nextTick(() => this.error$.next(error));
    throw error;
  }

  private updateState(response: IgResponse<any>) {
    const {
      'x-ig-set-www-claim': wwwClaim,
      'ig-set-authorization': auth,
      'ig-set-password-encryption-key-id': pwKeyId,
      'ig-set-password-encryption-pub-key': pwPubKey,
    } = response.headers;
    if (typeof wwwClaim === 'string') {
      this.client.state.igWWWClaim = wwwClaim;
    }
    if (typeof auth === 'string' && !auth.endsWith(':')) {
      this.client.state.authorization = auth;
    }
    if (typeof pwKeyId === 'string') {
      this.client.state.passwordEncryptionKeyId = pwKeyId;
    }
    if (typeof pwPubKey === 'string') {
      this.client.state.passwordEncryptionPubKey = pwPubKey;
    }
  }

  public signature(data: string) {
    return createHmac('sha256', this.client.state.signatureKey)
      .update(data)
      .digest('hex');
  }

  public sign(payload: Payload): SignedPost {
    const json = typeof payload === 'object' ? JSON.stringify(payload) : payload;
    const signature = this.signature(json);
    return {
      ig_sig_key_version: this.client.state.signatureVersion,
      signed_body: `${signature}.${json}`,
    };
  }

  public userBreadcrumb(size: number) {
    const term = random(2, 3) * 1000 + size + random(15, 20) * 1000;
    const textChangeEventCount = Math.round(size / random(2, 3)) || 1;
    const data = `${size} ${term} ${textChangeEventCount} ${Date.now()}`;
    const signature = Buffer.from(
      createHmac('sha256', this.client.state.userBreadcrumbKey)
        .update(data)
        .digest('hex'),
    ).toString('base64');
    const body = Buffer.from(data).toString('base64');
    return `${signature}\n${body}\n`;
  }

  private handleResponseError(response: Response): IgClientError {
    Request.requestDebug(
      `Request ${response.request.method} ${response.request.uri.path} failed: ${
        typeof response.body === 'object' ? JSON.stringify(response.body) : response.body
      }`,
    );

    const json = response.body;
    if (json.spam) {
      return new IgActionSpamError(response);
    }
    if (response.statusCode === 404) {
      return new IgNotFoundError(response);
    }
    if (typeof json.message === 'string') {
      if (json.message === 'challenge_required') {
        this.client.state.checkpoint = json;
        return new IgCheckpointError(response);
      }
      if (json.message === 'user_has_logged_out') {
        return new IgUserHasLoggedOutError(response);
      }
      if (json.message === 'login_required') {
        return new IgLoginRequiredError(response);
      }
      if (json.message.toLowerCase() === 'not authorized to view user') {
        return new IgPrivateUserError(response);
      }
    }
    if (json.error_type === 'sentry_block') {
      return new IgSentryBlockError(response);
    }
    if (json.error_type === 'inactive user') {
      return new IgInactiveUserError(response);
    }
    return new IgResponseError(response);
  }

  protected async faultTolerantRequest(options: OptionsInit) {
    try {
      return await retry(
        async () => got.extend({ prefixUrl: 'https://i.instagram.com' })(options),
        this.attemptOptions,
      );
    } catch (err) {
      console.log('err', err);
      throw new IgNetworkError(err);
    }
  }

  public getDefaultHeaders() {
    return {
      'user-agent': this.client.state.appUserAgent,
      'x-ads-opt-out': this.client.state.adsOptOut ? '1' : '0',
      'x-device-id': this.client.state.uuid,
      'x-cm-bandwidth-kbps': '-1.000',
      'x-cm-latency': '-1.000',
      'x-ig-app-locale': this.client.state.language,
      'x-ig-device-locale': this.client.state.language,
      'x-ig-mapped-locale': this.client.state.language,
      'x-pigeon-session-id': this.client.state.pigeonSessionId,
      'x-pigeon-rawclienttime': (Date.now() / 1000).toFixed(3),
      'x-ig-connection-speed': `${random(1000, 3700)}kbps`,
      'x-ig-bandwidth-speed-kbps': '-1.000',
      'x-ig-bandwidth-totalbytes-b': '0',
      'x-ig-bandwidth-totaltime-ms': '0',
      'X-IG-EU-DC-ENABLED':
        typeof this.client.state.euDCEnabled === 'undefined' ? void 0 : this.client.state.euDCEnabled.toString(),
      'X-IG-Extended-CDN-Thumbnail-Cache-Busting-Value': this.client.state.thumbnailCacheBustingValue.toString(),
      'x-ig-app-startup-country': 'unknown',
      'x-fb-client-ip': 'True',
      'x-fb-server-cluster': 'True',
      will_sound_on: '0',
      is_dark_mode: '0',
      priority: 'u=0',
      'x-ig-EU-DC-ENABLED':
        typeof this.client.state.euDCEnabled === 'undefined' ? void 0 : this.client.state.euDCEnabled.toString(),
      'x-bloks-version-id': this.client.state.bloksVersionId,
      'x-mid': this.client.state.extractCookie('mid')?.value,
      'x-ig-www-claim': this.client.state.igWWWClaim || '0',
      'x-bloks-is-layout-rtl': this.client.state.isLayoutRTL.toString(),
      'x-ig-connection-type': this.client.state.connectionTypeHeader,
      'x-ig-capabilities': this.client.state.capabilitiesHeader,
      'x-ig-app-id': this.client.state.fbAnalyticsApplicationId,
      'x-ig-device-id': this.client.state.uuid,
      'x-ig-android-id': this.client.state.deviceId,
      'accept-language': this.client.state.language.replace('_', '-'),
      'x-fb-http-engine': 'Liger',
      Authorization: this.client.state.authorization,
      'accept-encoding': 'gzip',
    };
  }
}
