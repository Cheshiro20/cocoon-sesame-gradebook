use std::collections::{HashMap, HashSet};

use sesame::context::{Context, UnprotectedContext};
use sesame::extensions::{ExtensionContext, SesameRefExtension};
use sesame::pcon::PCon;
use sesame::policy::{Reason, SimplePolicy as SesameSimplePolicy};

#[derive(Clone, Debug)]
pub struct ACLPolicy {
    pub owners: HashSet<String>,
}

impl ACLPolicy {
    pub fn new<I, S>(owners: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            owners: owners.into_iter().map(Into::into).collect(),
        }
    }
}

// Current Sesame app-facing policy interface.
impl SesameSimplePolicy for ACLPolicy {
    fn simple_name(&self) -> String {
        format!("ACLPolicy({:?})", self.owners)
    }

    fn simple_check(&self, context: &UnprotectedContext, _reason: Reason<'_>) -> bool {
        match context.downcast_ref::<String>() {
            Some(user) => self.owners.contains(user),
            None => false,
        }
    }

    // When two protected values are combined, keep only the users
    // who are allowed by both policies.
    fn simple_join_direct(&mut self, other: &mut Self) {
        self.owners = self
            .owners
            .intersection(&other.owners)
            .cloned()
            .collect();

        if self.owners.is_empty() {
            panic!("Unsatisfiable policy join");
        }
    }
}

type GradePCon = PCon<i32, ACLPolicy>;
type Grades = HashMap<String, GradePCon>;

// A small read extension: if Sesame approves the policy check,
// extract the protected i32.
struct ReadGrade;

impl<'a> SesameRefExtension<'a, i32, ACLPolicy, i32> for ReadGrade {
    fn apply_ref(&mut self, data: &'a i32, _policy: &'a ACLPolicy) -> i32 {
        *data
    }
}

fn main() {
    println!("=== Sesame Secure Gradebook ===");
    demo_secure();
}

fn make_secure_gradebook() -> (Grades, Grades, Grades) {
    // Each student's grades can be read by that student and by Teacher.
    let policy_a = ACLPolicy::new(["Alice", "Teacher"]);
    let policy_b = ACLPolicy::new(["Bob", "Teacher"]);
    let policy_c = ACLPolicy::new(["Carol", "Teacher"]);

    let alice = HashMap::from([
        (String::from("Math"), PCon::new(85, policy_a.clone())),
        (String::from("History"), PCon::new(72, policy_a.clone())),
    ]);

    let bob = HashMap::from([
        (String::from("Math"), PCon::new(90, policy_b.clone())),
        (String::from("History"), PCon::new(65, policy_b.clone())),
    ]);

    let carol = HashMap::from([
        (String::from("Math"), PCon::new(58, policy_c.clone())),
        (String::from("History"), PCon::new(80, policy_c.clone())),
    ]);

    (alice, bob, carol)
}

fn read_grade_as(grade: &GradePCon, username: &str) -> Result<i32, String> {
    // Build a small test context from the username.
    let ctx = ExtensionContext::new(Context::test(username.to_string()));
    let mut reader = ReadGrade;
    let reason_tag = ();

    grade
        .checked_extension_ref(&mut reader, &ctx, Reason::Custom(&reason_tag))
        .map_err(|e| e.to_string())
}

fn overall_average_secure(
    alice: &Grades,
    bob: &Grades,
    carol: &Grades,
    subject: &str,
    viewer: &str,
) -> Result<f64, String> {
    let mut sum = 0;
    let mut count = 0;

    for grades in [alice, bob, carol] {
        if let Some(g) = grades.get(subject) {
            sum += read_grade_as(g, viewer)?;
            count += 1;
        }
    }

    if count == 0 {
        return Err(format!("No grades found for subject: {}", subject));
    }

    Ok(sum as f64 / count as f64)
}

fn pass_fail_summary_secure(
    alice: &Grades,
    bob: &Grades,
    carol: &Grades,
    subject: &str,
    pass_threshold: i32,
    viewer: &str,
) -> Result<HashMap<String, bool>, String> {
    let mut result = HashMap::new();

    if let Some(g) = alice.get(subject) {
        let grade = read_grade_as(g, viewer)?;
        result.insert(String::from("Alice"), grade >= pass_threshold);
    }

    if let Some(g) = bob.get(subject) {
        let grade = read_grade_as(g, viewer)?;
        result.insert(String::from("Bob"), grade >= pass_threshold);
    }

    if let Some(g) = carol.get(subject) {
        let grade = read_grade_as(g, viewer)?;
        result.insert(String::from("Carol"), grade >= pass_threshold);
    }

    if result.is_empty() {
        return Err(format!("No grades found for subject: {}", subject));
    }

    Ok(result)
}

fn demo_secure() {
    let (alice, bob, carol) = make_secure_gradebook();

    // --- Sesame-specific ACL demo ---

    // Alice can read Alice's own grade.
    match read_grade_as(alice.get("Math").unwrap(), "Alice") {
        Ok(v) => println!("Alice reads her Math grade: {}", v),
        Err(e) => println!("Alice failed to read her Math grade: {}", e),
    }

    // Alice should NOT be able to read Bob's grade.
    match read_grade_as(bob.get("Math").unwrap(), "Alice") {
        Ok(v) => println!("Alice unexpectedly read Bob's Math grade: {}", v),
        Err(e) => println!("Alice cannot read Bob's Math grade: {}", e),
    }

    // --- More directly comparable to the Cocoon version ---

    // Teacher computes Math average.
    match overall_average_secure(&alice, &bob, &carol, "Math", "Teacher") {
        Ok(avg) => println!("(secure) Math average (Teacher-authorized)    = {:.1}", avg),
        Err(e) => println!("Teacher failed to compute Math average: {}", e),
    }

    // Teacher computes History average.
    match overall_average_secure(&alice, &bob, &carol, "History", "Teacher") {
        Ok(avg) => println!("(secure) History average (Teacher-authorized) = {:.1}", avg),
        Err(e) => println!("Teacher failed to compute History average: {}", e),
    }

    // Teacher computes Math pass/fail summary.
    match pass_fail_summary_secure(&alice, &bob, &carol, "Math", 60, "Teacher") {
        Ok(pass_map) => {
            println!("\n(secure) Math pass/fail (Teacher-authorized):");
            for name in ["Alice", "Bob", "Carol"] {
                if let Some(ok) = pass_map.get(name) {
                    println!("  {}: {}", name, if *ok { "pass" } else { "fail" });
                }
            }
        }
        Err(e) => println!("Teacher failed to compute pass/fail summary: {}", e),
    }
}