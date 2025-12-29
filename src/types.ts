export type CheckDGHashesInput = Record<number, Uint8Array>;

export enum DataGroupDetailedResultCode {
    ERROR = 0,
    SUCCESS = 1,
    SKIPPED = 2
}

export interface DataGroupDetailedResult {
    datagroup: number;
    result: DataGroupDetailedResultCode;
}

export interface CheckDGHashesResult {
    result: boolean; 
    detailed: DataGroupDetailedResult[];
}