export type CheckDGHashesInput = Record<number, Uint8Array>;

export enum DataGroupDetailedResultCode {
    ERROR,
    SUCCESS,
    SKIPPED
}

export interface DataGroupDetailedResult {
    datagroup: number;
    result: DataGroupDetailedResultCode;
}

export interface CheckDGHashesResult {
    result: boolean; 
    detailed: DataGroupDetailedResult[];
}