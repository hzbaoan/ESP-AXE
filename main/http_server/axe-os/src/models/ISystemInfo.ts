import { eASICModel } from './enum/eASICModel';

interface ISharesRejectedStat {
    message: string;
    count: number;
}

export interface ISystemInfo {

    flipscreen: number;
    invertscreen: number;
    power: number,
    voltage: number,
    current: number,
    temp: number,
    vrTemp: number,
    maxPower: number,
    nominalVoltage: number,
    hashRate: number,
    bestDiff: string,
    bestSessionDiff: string,
    freeHeap: number,
    coreVoltage: number,
    hostname: string,
    macAddr: string,
    ssid: string,
    wifiStatus: string,
    apEnabled: number,
    sharesAccepted: number,
    sharesRejected: number,
    sharesRejectedReasons: ISharesRejectedStat[];
    uptimeSeconds: number,
    asicCount: number,
    smallCoreCount: number,
    ASICModel: eASICModel,
    stratumProtocol: number,
    fallbackStratumProtocol: number,
    stratumURL: string,
    stratumPort: number,
    fallbackStratumURL: string,
    fallbackStratumPort: number,
    isUsingFallbackStratum: boolean,
    stratumUser: string,
    fallbackStratumUser: string,
    sv2Host: string,
    sv2Port: number,
    sv2AuthorityPublicKey: string,
    fallbackSv2Host: string,
    fallbackSv2Port: number,
    fallbackSv2AuthorityPublicKey: string,
    socks5ProxyEnabled: number,
    socks5ProxyHost: string,
    socks5ProxyPort: number,
    socks5ProxyUser: string,
    frequency: number,
    version: string,
    idfVersion: string,
    boardVersion: string,
    invertfanpolarity: number,
    autofanspeed: number,
    fanspeed: number,
    fanrpm: number,
    coreVoltageActual: number,

    boardtemp1?: number,
    boardtemp2?: number,
    overheat_mode: number,
    power_fault?: string,
    overclockEnabled?: number,
    chipSubmitStr: string,
}
