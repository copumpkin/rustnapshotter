#[macro_use]
extern crate json;

extern crate url;
extern crate futures;
extern crate tokio_core;

extern crate rusoto_core;
extern crate rusoto_sts;
extern crate rusoto_iam;
extern crate rusoto_s3;

use std::collections::HashMap;

use url::percent_encoding::percent_decode;
use tokio_core::reactor::Core;

use futures::future::{IntoFuture, Future, ok, FutureResult, loop_fn, Loop, LoopFn}; 
use rusoto_core::{Region, HttpClient, RusotoFuture, CredentialsError, HttpDispatchError};
use rusoto_sts::{Sts, StsClient, StsAssumeRoleSessionCredentialsProvider};
use rusoto_iam::{Iam, IamClient, GetAccountAuthorizationDetailsRequest, GetAccountAuthorizationDetailsError, ListEntitiesForPolicyRequest};
//use rusoto_s3::{S3, S3Client};

/*
fn paginate<'a, Req, Resp, Err, S, R>(
            req: &'static mut Req,
            state: &'static mut S,
            end: &'a impl FnOnce(&mut S) -> R,
            request: &'a impl Fn(Req) -> RusotoFuture<Resp, Err>,
            get_marker: &'static impl Fn(&Resp) -> &Option<String>,
            set_marker: &'a impl Fn(&mut Req, &Option<String>) -> (),
            handle: &'static impl Fn(&Resp, &mut S)) -> &'static impl Future<Item=R, Error=Err>
        where
        Req: Clone,
        Resp: Send + 'static,
        Err: From<CredentialsError> + From<HttpDispatchError> + Send + 'static {

    /*
    fn iter()

    let iter = || {
        request(req.clone()).then(|res| {
            iter()
        })

        /*
        match request(req.clone()).sync() {
            Ok(output) => {
                handle(&output, state);
                let marker = getMarker(&output);
                setMarker(req, &marker);
                if marker.is_none() {
                    break;
                }
            },
            Err(err) => {

            }
        }
        */       
    };

    iter()
    */

    let x = loop_fn(state, |mut state| {
        request(req.clone()).then(|res| {
            match res {
                Ok(output) => {
                    handle(&output, state);
                    let marker = get_marker(&output);
                    set_marker(req, &marker);
                    if marker.is_none() {
                        Ok(Loop::Break(end(state)))
                    } else {
                        Ok(Loop::Continue(state))
                    }
                },
                Err(err) => {
                    Ok(Loop::Continue(state))
                }   
            }
        })
    });

    &x
}
*/

// https://github.com/rusoto/rusoto/issues/1287
fn percent_json(input: &str) -> json::JsonValue {
    // Ick
    json::parse(&percent_decode(input.as_bytes()).decode_utf8().unwrap()).unwrap()
}

struct Scheduler {

}

fn snapshot_iam(scheduler: Scheduler, iam_client: IamClient) {

    // Generalizing this a bit in preparation for generalizing over pagination as in the commented-out monstrosity above
    struct State<Req, Inner> {
        req:   Req,
        inner: Inner
    };

    struct IamState {
        policies:        json::object::Object,
        roles:           json::object::Object,
        users:           json::object::Object,
        groups:          json::object::Object,
        boundaries:      HashMap<String, String>,
        group_interests: HashMap<String, Vec<String>>,
        group_arns:      HashMap<String, String>
    };

    let iter = loop_fn(
        State {
            req:   GetAccountAuthorizationDetailsRequest::default(),
            inner: IamState {
                policies:        json::object::Object::new(),
                roles:           json::object::Object::new(),
                users:           json::object::Object::new(),
                groups:          json::object::Object::new(),
                boundaries:      HashMap::new(),
                group_interests: HashMap::new(),
                group_arns:      HashMap::new()
            }
        },
        |mut state| {
            iam_client.get_account_authorization_details(state.req.clone()).then(|res| {
                match res {
                    Ok(output) => {
                        for policy in output.policies.unwrap_or(vec!()) {
                            let arn = policy.arn.unwrap();

                            for version in policy.policy_version_list.unwrap_or(vec!()) {
                                if version.is_default_version.unwrap() {
                                    state.inner.policies[arn.clone()] = percent_json(&version.document.unwrap());
                                }
                            }
                            assert!(state.inner.policies.get(&arn).is_some(), "no default version found for '{}'", arn);

                            if policy.permissions_boundary_usage_count.unwrap() > 0 {
                                let req = ListEntitiesForPolicyRequest {
                                    policy_arn: arn.clone(),
                                    policy_usage_filter: Some("PermissionsBoundary".to_string()),
                                    ..Default::default()
                                };

                                // FIXME: don't sync!!
                                match iam_client.list_entities_for_policy(req).sync() {
                                    Ok(res)  => {
                                        for role in res.policy_roles.unwrap() {
                                            state.inner.boundaries.insert(role.role_id.unwrap(), arn.clone());
                                        }

                                        for user in res.policy_users.unwrap() {
                                            state.inner.boundaries.insert(user.user_id.unwrap(), arn.clone());
                                        }

                                        // Groups can't have permission boundaries on them
                                        // XXX: paginate these results
                                    },
                                    Err(err) => {}
                                };
                            }
                        }

                        for role in output.role_detail_list.unwrap_or(vec!()) {
                            let mut inline_policies = object!{};

                            for policy in role.role_policy_list.unwrap_or(vec!()) {
                                inline_policies[policy.policy_name.unwrap()] = percent_json(&policy.policy_document.unwrap());
                            }

                            state.inner.roles[role.arn.unwrap()] = object!{
                                "id"                  => role.role_id.unwrap(),
                                "managed_policy_arns" => role.attached_managed_policies.unwrap().into_iter().map(|x| x.policy_arn.unwrap()).collect::<Vec<_>>(),
                                "assume_role_policy"  => percent_json(&role.assume_role_policy_document.unwrap()),
                                "inline_policies"     => inline_policies,
                                "boundary"            => json::JsonValue::Null,
                                "tags"                => object!{} // TODO: fill this in
                            };
                        }

                        
                        for user in output.user_detail_list.unwrap_or(vec!()) {
                            let arn = user.arn.unwrap();
                            let mut inline_policies = object!{};

                            for policy in user.user_policy_list.unwrap_or(vec!()) {
                                inline_policies[policy.policy_name.unwrap()] = percent_json(&policy.policy_document.unwrap());
                            }

                            state.inner.users[arn.clone()] = object!{
                                "id"                  => user.user_id.unwrap(),
                                "managed_policy_arns" => user.attached_managed_policies.unwrap().into_iter().map(|x| x.policy_arn.unwrap()).collect::<Vec<_>>(),
                                "inline_policies"     => inline_policies,
                                "boundary"            => json::JsonValue::Null,
                                "groups"              => Vec::<String>::new(),
                                "tags"                => object!{} // TODO: fill this in
                            };

                            for group in user.group_list.unwrap_or(vec!()) {
                                state.inner.group_interests.entry(group.clone()).or_insert(vec!()).push(arn.clone());
                            }
                        }

                        for group in output.group_detail_list.unwrap_or(vec!()) {
                            let arn = group.arn.unwrap();
                            let mut inline_policies = object!{};

                            for policy in group.group_policy_list.unwrap_or(vec!()) {
                                inline_policies[policy.policy_name.unwrap()] = percent_json(&policy.policy_document.unwrap());
                            }

                            state.inner.group_arns.insert(group.group_name.unwrap().clone(), arn.clone());

                            state.inner.groups[arn.clone()] = object!{
                                "id"                  => group.group_id.unwrap(),
                                "managed_policy_arns" => group.attached_managed_policies.unwrap().into_iter().map(|x| x.policy_arn.unwrap()).collect::<Vec<_>>(),
                                "inline_policies"     => inline_policies
                            };
                        }

                        match output.marker {
                            Some(marker) => {
                                state.req.marker = Some(marker);
                                ok(Loop::Continue(state)) as FutureResult<_, ()>
                            },
                            None => ok(Loop::Break(state.inner))
                        }
                    },
                    Err(err) => {
                        ok(Loop::Continue(state))
                    }
                }   
            })
        }
    );

    let mut core = Core::new().unwrap();

    match core.run(iter) {
        Ok(mut state) => {
            for (k, v) in state.roles.iter_mut().chain(state.users.iter_mut()) {
                match state.boundaries.get(v["id"].as_str().unwrap()) {
                    Some(boundary_arn) => { v["boundary"] = json::JsonValue::String(boundary_arn.clone()); },
                    None => {}
                }
            }

            for (k, v) in state.group_interests.iter() {
                for user_arn in v.iter() {
                    state.users[user_arn]["groups"].push(state.group_arns[k].clone());
                }
            }

            let out = object!{
                "policies" => state.policies,
                "roles"    => state.roles,
                "users"    => state.users,
                "groups"   => state.groups
            };

            println!("{}", out.pretty(2));
        },
        Err(err) => {}
    }

/*
    while !done {
        match iam_client.get_account_authorization_details(req.clone()).sync() {
            Ok(output) => {
                for policy in output.policies.unwrap() {
                    policies.push(policy.arn.clone());
                    println!("policy {}", policy.arn.unwrap());
                }

                for role in output.role_detail_list.unwrap() {
                    println!("zomg {}", role.arn.unwrap());
                }

                for user in output.user_detail_list.unwrap() {
                    println!("zomg! {}", user.arn.unwrap());
                }

                for group in output.group_detail_list.unwrap() {
                    println!("group! {}", group.arn.unwrap());
                }

                match output.marker {
                    Some(marker) => req.marker = Some(marker),
                    None => done = true
                }
            },
            Err(GetAccountAuthorizationDetailsError::Unknown(error)) => {
                let err = std::str::from_utf8(&error.body).unwrap();
                println!("zomg nooooo {}", err)
            },
            Err(_) => println!("zomg nooooo")
        }
    }
*/

}

fn main() {
    //let client = S3Client::new(Region::UsEast1);

    let iam = IamClient::new(Region::UsEast1);

    snapshot_iam(Scheduler {}, iam);

    let sts = StsClient::new(Region::UsEast1);

    // XXX: https://github.com/rusoto/rusoto/pull/1181/files
    let provider = StsAssumeRoleSessionCredentialsProvider::new(
        sts,
        "arn:aws:iam::12345:role/Foo".to_owned(),
        "my_session_id".to_owned(),
        None, None, None, None
    );

    let child_client = StsClient::new_with(HttpClient::new().unwrap(), provider, Region::UsEast1);

    match child_client.get_caller_identity(Default::default()).sync() {
      Ok(output) => {
        match output.arn {
          Some(arn) => println!("my arn is {}", arn),
          None => println!("no arn :(")
        }
      },
      Err(error) => {
        println!("zomg noooooo");
      }
    }

    /*
    match client.list_buckets().sync() {
        Ok(output) => {
            match output.buckets {
                Some(bucket_list) => {
                    println!("Buckets:");

                    for bucket in bucket_list {
                      match bucket.name {
                        Some(name) => println!("{}", name),
                        None => println!("Whoa missing name")
                      }
                    }
                },
                None => println!("No buckets!"),
            }
        },
        Err(error) => {
            println!("Error: {:?}", error);
        },
    }
    */
}
