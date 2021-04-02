type HttpScanRule = {
  name: string;
  output: {
    [any: string]: any;
  };
  pass: boolean;
  result: string;
  score_description: string;
  score_modifier: number;
};

type HttpScanRules = {
  [any: string]: HttpScanRule;
};

type HttpScanResult = {
  url: string;
  scan_id: number;
  grade: string;
  score: number;
  details: HttpScanRules;
};
