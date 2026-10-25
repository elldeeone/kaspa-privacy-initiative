// Retain immutable public templates until all queued work has been consumed.
// This module has no SDK, wallet, network, signing or broadcast authority.
export class MiningJobs {
  jobs = new Map();
  queued = [];
  retain(job) {
    const previous=this.jobs.get(job.id);
    if(previous){
      if(previous.identity!==job.identity)throw new Error('same PoW job changed body');
      return previous;
    }
    this.jobs.set(job.id,job);return job;
  }
  offer(message){this.queued.push(message);}
  async drain(consume){
    while(this.queued.length){
      const message=this.queued.shift(),job=this.jobs.get(message.id);
      if(job&&!job.used)await consume(message,job);
    }
  }
  async during(operation,consume){
    // Slow Tor requests cannot hide a pending nonce or erase its old template.
    await this.drain(consume);
    const result=await operation();
    await this.drain(consume);
    return result;
  }
}
