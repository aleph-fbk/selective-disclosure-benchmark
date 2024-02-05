use ursa_benchmark::MESSAGE_COUNT_RANGE;
use criterion::{
    black_box, 
    criterion_group, 
    criterion_main, 
    BenchmarkId, 
    Criterion,
};
use ursa::cl::{
    issuer::Issuer, 
    CredentialSchema,
};
use std::collections::BTreeSet;

fn cl_keygen_benchmark(c:&mut Criterion) {

    let messages_range = MESSAGE_COUNT_RANGE
        .iter()
        .map(|m| {
            (0..*m)
                .map(|i| format!("{}", i))
                .collect::<BTreeSet<_>>()
        })
        .collect::<Vec<_>>();
    
    let credential_schema_range = messages_range
        .iter()
        .map(|m| CredentialSchema {
                attrs: m.clone() //attr names
            }).collect::<Vec<_>>();

    let nc_schema = Issuer::new_non_credential_schema_builder().unwrap().finalize().unwrap();
    
    let mut keygen_group = c.benchmark_group("ursa CL keygen");
    for (i, count) in MESSAGE_COUNT_RANGE.iter().enumerate() {
        keygen_group.bench_with_input(
            BenchmarkId::from_parameter(*count),
            &i, 
            |b, &i| { b.iter(|| {
                //follows what we are benchmarking in this group
                //note that in the cl_setup we are building a lot more but this should give us a 
                //private key and a public key which is just what we want
                
                Issuer::_new_credential_primary_keys_set(
                    black_box(&credential_schema_range[i]),
                    black_box(&nc_schema)
                ).unwrap()
            });
        });       
    } keygen_group.finish();
}

criterion_group!(benches, cl_keygen_benchmark);
criterion_main!(benches);