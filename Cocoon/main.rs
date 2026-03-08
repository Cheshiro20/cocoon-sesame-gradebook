use std::collections::HashMap;

use secret_structs::secret::*;
use secret_structs::lattice as lat;
use secret_macros::*;


type Grades<L> = HashMap<String, Secret<i32, L>>;

fn main() {
    println!("=== Insecure gradebook ===");
    demo_insecure();

    println!("\n=== Cocoon secure gradebook ===");
    demo_secure();
}


fn make_insecure_gradebook(
) -> (
    HashMap<String, i32>,
    HashMap<String, i32>,
    HashMap<String, i32>,
) {
    
    let alice = HashMap::from([
        (String::from("Math"), 85),
        (String::from("History"), 72),
    ]);

    let bob = HashMap::from([
        (String::from("Math"), 90),
        (String::from("History"), 65),
    ]);

    let carol = HashMap::from([
        (String::from("Math"), 58),
        (String::from("History"), 80),
    ]);

    (alice, bob, carol)
}


fn overall_average_insecure(
    alice: &HashMap<String, i32>,
    bob: &HashMap<String, i32>,
    carol: &HashMap<String, i32>,
    subject: &str,
) -> Option<f64> {
    let mut sum = 0;
    let mut count = 0;

    if let Some(g) = alice.get(subject) {
        sum += *g;
        count += 1;
    }
    if let Some(g) = bob.get(subject) {
        sum += *g;
        count += 1;
    }
    if let Some(g) = carol.get(subject) {
        sum += *g;
        count += 1;
    }

    if count == 0 {
        None
    } else {
        Some(sum as f64 / count as f64)
    }
}

fn demo_insecure() {
    let (alice, bob, carol) = make_insecure_gradebook();

    if let Some(avg) = overall_average_insecure(&alice, &bob, &carol, "Math") {
        println!("(insecure) Math average = {:.1}", avg);
    }
    if let Some(avg) = overall_average_insecure(&alice, &bob, &carol, "History") {
        println!("(insecure) History average = {:.1}", avg);
    }

   
    println!("\n(insecure) Raw grades for Math:");
    println!("  Alice: {:?}", alice.get("Math"));
    println!("  Bob  : {:?}", bob.get("Math"));
    println!("  Carol: {:?}", carol.get("Math"));
}


fn make_secure_gradebook(
) -> (
    Grades<lat::Label_A>,
    Grades<lat::Label_B>,
    Grades<lat::Label_C>,
) {
    let alice = HashMap::from([
        (
            String::from("Math"),
            unsafe { Secret::<i32, lat::Label_A>::new(85) },
        ),
        (
            String::from("History"),
            unsafe { Secret::<i32, lat::Label_A>::new(72) },
        ),
    ]);

    let bob = HashMap::from([
        (
            String::from("Math"),
            unsafe { Secret::<i32, lat::Label_B>::new(90) },
        ),
        (
            String::from("History"),
            unsafe { Secret::<i32, lat::Label_B>::new(65) },
        ),
    ]);

    let carol = HashMap::from([
        (
            String::from("Math"),
            unsafe { Secret::<i32, lat::Label_C>::new(58) },
        ),
        (
            String::from("History"),
            unsafe { Secret::<i32, lat::Label_C>::new(80) },
        ),
    ]);

    (alice, bob, carol)
}



fn overall_average_secure<
    LA: lat::Label,
    LB: lat::Label,
    LC: lat::Label,
    Ret: lat::Label,
>(
    alice: &Grades<LA>,
    bob: &Grades<LB>,
    carol: &Grades<LC>,
    subject: &str,
) -> Secret<f64, Ret>
where
    Ret: lat::MoreSecretThan<LA> + lat::MoreSecretThan<LB> + lat::MoreSecretThan<LC>,
{
   
    secret_block!(Ret {
        let mut sum = 0;
        let mut count = 0;

        
        if std::collections::HashMap::contains_key(alice, subject) {
            let g = std::option::Option::unwrap(std::collections::HashMap::get(
                alice, subject,
            ));
            sum += *unwrap_secret_ref(g);
            count += 1;
        }

        if std::collections::HashMap::contains_key(bob, subject) {
            let g = std::option::Option::unwrap(std::collections::HashMap::get(
                bob, subject,
            ));
            sum += *unwrap_secret_ref(g);
            count += 1;
        }

        if std::collections::HashMap::contains_key(carol, subject) {
            let g = std::option::Option::unwrap(std::collections::HashMap::get(
                carol, subject,
            ));
            sum += *unwrap_secret_ref(g);
            count += 1;
        }

        let avg = if count == 0 {
            0.0
        } else {
            (sum as f64) / (count as f64)
        };

        wrap_secret(avg)
    })
}


fn pass_fail_summary_secure<
    LA: lat::Label,
    LB: lat::Label,
    LC: lat::Label,
    Ret: lat::Label,
>(
    alice: &Grades<LA>,
    bob: &Grades<LB>,
    carol: &Grades<LC>,
    subject: &str,
    pass_threshold: i32,
) -> Secret<HashMap<&'static str, bool>, Ret>
where
    Ret: lat::MoreSecretThan<LA> + lat::MoreSecretThan<LB> + lat::MoreSecretThan<LC>,
{
  
    let mut result: Secret<HashMap<&'static str, bool>, Ret> =
        unsafe { Secret::<HashMap<&'static str, bool>, Ret>::new(HashMap::new()) };

    
    secret_block!(Ret {
        // Alice
        if std::collections::HashMap::contains_key(alice, subject) {
            let g = std::option::Option::unwrap(std::collections::HashMap::get(
                alice, subject,
            ));
            let passed = *unwrap_secret_ref(g) >= pass_threshold;
            let r = unwrap_secret_mut_ref(&mut result);
            std::collections::HashMap::insert(r, "Alice", passed);
        }

        // Bob
        if std::collections::HashMap::contains_key(bob, subject) {
            let g = std::option::Option::unwrap(std::collections::HashMap::get(
                bob, subject,
            ));
            let passed = *unwrap_secret_ref(g) >= pass_threshold;
            let r = unwrap_secret_mut_ref(&mut result);
            std::collections::HashMap::insert(r, "Bob", passed);
        }

        // Carol
        if std::collections::HashMap::contains_key(carol, subject) {
            let g = std::option::Option::unwrap(std::collections::HashMap::get(
                carol, subject,
            ));
            let passed = *unwrap_secret_ref(g) >= pass_threshold;
            let r = unwrap_secret_mut_ref(&mut result);
            std::collections::HashMap::insert(r, "Carol", passed);
        }
    });

    result
}

fn demo_secure() {
    let (alice, bob, carol) = make_secure_gradebook();

   
    let math_avg: Secret<f64, lat::Label_ABC> =
        overall_average_secure::<lat::Label_A, lat::Label_B, lat::Label_C, lat::Label_ABC>(
            &alice, &bob, &carol, "Math",
        );
    let history_avg: Secret<f64, lat::Label_ABC> =
        overall_average_secure::<lat::Label_A, lat::Label_B, lat::Label_C, lat::Label_ABC>(
            &alice, &bob, &carol, "History",
        );

    println!(
        "(secure) Math average (declassified)    = {:.1}",
        math_avg.declassify().get_value_consume()
    );
    println!(
        "(secure) History average (declassified) = {:.1}",
        history_avg.declassify().get_value_consume()
    );

    let pass_map_math: Secret<HashMap<&'static str, bool>, lat::Label_ABC> =
        pass_fail_summary_secure::<lat::Label_A, lat::Label_B, lat::Label_C, lat::Label_ABC>(
            &alice, &bob, &carol, "Math", 60,
        );

    let pass_map = pass_map_math.declassify().get_value_consume();
    println!("\n(secure) Math pass/fail (declassified only once):");
    for (name, ok) in pass_map {
        println!("  {}: {}", name, if ok { "pass" } else { "fail" });
    }
}
