## Cocoon vs. Sesame on a Gradebook Example

### Implementation
I implemented the same gradebook-style example in Cocoon and Sesame. The scenario involves three students (Alice, Bob, Carol) and two subjects (Math, History). Operations implemented include subject average and pass/fail summary (threshold = 60). 

* **Sesame specific:** The Sesame version additionally demonstrates per-user access control: Alice can read her own grade but cannot read Bob’s grade, while the teacher can read all grades and compute aggregates. *(Example output: Alice reads her Math grade: 85; Alice cannot read Bob's Math grade; Math average = 77.7; History average = 72.3; Math pass/fail: Alice: pass, Bob: pass, Carol: fail).*

### Representation of Protected Data
* **Cocoon (`Secret<i32, Label>`):** Labels are part of the type and lattice relationships determine allowed flows. 
* **Sesame (`PCon<i32, Policy>`):** Data is wrapped in policy containers and policies define who can access the data.

### Aggregate Computation
* **Cocoon:** Computation happens inside `secret_block!`, secret values are accessed via `unwrap_secret_ref`, and the result must be explicitly `declassify()` before release. 
* **Sesame:** Grades are accessed via a policy-checked interface, computation happens after authorized reads, and there is no explicit declassification step in this prototype.

### Implementation Burden
* **Cocoon:** The burden appears in label design, type constraints (`MoreSecretThan`), `secret_block!`, and explicit declassification. 
* **Sesame:** The burden appears in converting values to `PCon`, defining policies, and restructuring code around policy-checked access.

### Conclusion & Impressions
Even for a small example, the two systems shift complexity to different places. My current impression is that Cocoon and Sesame do not simply differ in syntax; **they shift the programming burden to different parts of the program.**

* **Cocoon** makes secrecy structure explicit in labels and types. It emphasizes protected computation followed by explicit declassification.
* **Sesame** makes access structure explicit through policy containers and policy-checked interfaces. In this benchmark, my current Sesame prototype emphasizes authorized access to protected data followed by ordinary computation.
