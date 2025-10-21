declare module 'node-fetch' {
  function fetch(url: string, init?: any): Promise<any>;
  export default fetch;
}
