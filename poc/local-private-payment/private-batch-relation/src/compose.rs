//! Exact three-signature matrix composition. Every original row/term is kept;
//! component public digest/AK edges become private in the final relation.
use crate::{BatchLayout, COMPONENT_INSTANCES, OWNERS};
use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, Field};
use auth::join::{Boundary, R1cs, Row};

#[derive(Clone)]
pub struct JoinedBatch {
    pub cs: R1cs,
    pub core_variables: usize,
    pub signature_variables: [usize; OWNERS],
    pub core_rows: usize,
    pub signature_rows: [usize; OWNERS],
}

impl JoinedBatch {
    /// Ordered private-input columns for each wallet: its native internal
    /// edges/auxiliaries and complete selected signature component. Global
    /// digest/core/state/permutation auxiliaries are deliberately excluded.
    pub fn owner_input_columns(&self,layout:&BatchLayout)->Result<[Vec<usize>;OWNERS],Boundary> {
        self.cs.validate()?;
        if self.cs.instances!=3||self.core_variables>self.cs.variables()?
            ||layout.effect_bit_columns!=(COMPONENT_INSTANCES..COMPONENT_INSTANCES+crate::EFFECT_BYTES*8).collect::<Vec<_>>()
            ||layout.initial_joint_columns.start!=COMPONENT_INSTANCES
            ||layout.initial_joint_columns.end<COMPONENT_INSTANCES+crate::EFFECT_BYTES*8
            ||layout.owner_local_columns[0].start!=layout.initial_joint_columns.end
            ||layout.owner_local_columns[OWNERS-1].end!=layout.final_joint_columns.start
            ||layout.final_joint_columns.end!=self.core_variables
            || layout.owner_local_columns.iter().any(|r|r.start<COMPONENT_INSTANCES||r.start>r.end||r.end>self.core_variables)
            || layout.owner_local_columns.windows(2).any(|p|p[0].end!=p[1].start)
        {return Err(Boundary::Shape);}
        let mut signature_start=self.core_variables;
        let mut owners=Vec::with_capacity(OWNERS);
        for i in 0..OWNERS {
            let local=layout.owner_local_columns[i];
            let mut columns=(3+66*i..3+66*(i+1)).collect::<Vec<_>>();
            columns.extend(local.start..local.end);
            let end=add(signature_start,self.signature_variables[i].checked_sub(1).ok_or(Boundary::Shape)?)?;
            columns.extend(signature_start..end);signature_start=end;
            if columns.windows(2).any(|p|p[0]>=p[1]) {return Err(Boundary::Column);}
            owners.push(columns);
        }
        if signature_start!=self.cs.variables()? {return Err(Boundary::Length);}
        owners.try_into().map_err(|_|Boundary::Shape)
    }
}

fn add(a: usize, b: usize) -> Result<usize, Boundary> {
    a.checked_add(b).ok_or(Boundary::Overflow)
}
fn equality(a: usize, b: usize) -> [Row; 3] {
    [
        vec![(Fr::ONE, a), (-Fr::ONE, b)],
        vec![(Fr::ONE, 0)],
        vec![],
    ]
}

pub fn join(core: &R1cs, signatures: &[R1cs; OWNERS]) -> Result<JoinedBatch, Boundary> {
    core.validate()?;
    if core.instances != COMPONENT_INSTANCES {
        return Err(Boundary::Shape);
    }
    let core_variables = core.variables()?;
    let mut matrices = core.matrices.clone();
    let mut variables = core_variables;
    let mut signature_variables = [0; OWNERS];
    let mut signature_rows = [0; OWNERS];
    for (owner, signature) in signatures.iter().enumerate() {
        signature.validate()?;
        if signature.instances != 67 {
            return Err(Boundary::Shape);
        }
        let n = signature.variables()?;
        let start = variables;
        let map = |i: usize| if i == 0 { 0 } else { start + i - 1 };
        variables = add(variables, n - 1)?;
        for axis in 0..3 {
            for row in &signature.matrices[axis] {
                let lifted: Row = row.iter().map(|(c, i)| (*c, map(*i))).collect();
                // This inverse check retains ordering, zero terms and duplicates.
                if lifted.iter().zip(row).any(|((a, i), (b, j))| {
                    a != b || (if *i == 0 { 0 } else { *i - start + 1 }) != *j
                }) {
                    return Err(Boundary::Inverse);
                }
                matrices[axis].push(lifted);
            }
        }
        signature_variables[owner] = n;
        signature_rows[owner] = signature.constraints();
    }
    let mut start = core_variables;
    for owner in 0..OWNERS {
        for edge in 0..66 {
            let rows = equality(3 + owner * 66 + edge, start + edge);
            for axis in 0..3 {
                matrices[axis].push(rows[axis].clone());
            }
        }
        start = add(start, signature_variables[owner] - 1)?;
    }
    let cs = R1cs {
        instances: 3,
        witnesses: variables.checked_sub(3).ok_or(Boundary::Shape)?,
        matrices,
    };
    cs.validate()?;
    Ok(JoinedBatch {
        cs,
        core_variables,
        signature_variables,
        core_rows: core.constraints(),
        signature_rows,
    })
}

pub fn assignment(
    joined: &JoinedBatch,
    core: &[Fr],
    signatures: &[Vec<Fr>; OWNERS],
) -> Result<Vec<Fr>, Boundary> {
    if core.len() != joined.core_variables || core.first() != Some(&Fr::ONE) {
        return Err(Boundary::Length);
    }
    let mut z = core.to_vec();
    for owner in 0..OWNERS {
        if signatures[owner].len() != joined.signature_variables[owner]
            || signatures[owner].first() != Some(&Fr::ONE)
        {
            return Err(Boundary::Length);
        }
        z.extend_from_slice(&signatures[owner][1..]);
    }
    if z.len() != joined.cs.variables()? {
        return Err(Boundary::Length);
    }
    Ok(z)
}

/// All actual residuals are evaluated; a checked assignment is not a proof.
pub fn residual_failures(joined: &JoinedBatch, z: &[Fr]) -> Result<usize, Boundary> {
    joined.cs.validate()?;
    if z.len() != joined.cs.variables()? || z.first() != Some(&Fr::ONE) {
        return Err(Boundary::Length);
    }
    let dot = |row: &Row| row.iter().fold(Fr::ZERO, |v, (c, i)| v + *c * z[*i]);
    Ok((0..joined.cs.constraints())
        .filter(|i| {
            dot(&joined.cs.matrices[0][*i]) * dot(&joined.cs.matrices[1][*i])
                != dot(&joined.cs.matrices[2][*i])
        })
        .count())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn component(instances: usize) -> R1cs {
        R1cs {
            instances,
            witnesses: 1,
            matrices: [
                vec![vec![(Fr::ONE, instances)]],
                vec![vec![(Fr::ONE, 0)]],
                vec![vec![(Fr::ONE, 1)]],
            ],
        }
    }
    #[test]
    fn three_full_components_link_without_publishing_owner_edges() {
        // These tiny rows test matrix composition, not a signature predicate.
        let joined = join(
            &component(COMPONENT_INSTANCES),
            &core::array::from_fn(|_| component(67)),
        )
        .unwrap();
        assert_eq!(joined.cs.instances, 3);
        assert_eq!(joined.cs.constraints(), 1 + 3 + 198);
        let core = vec![Fr::ONE; COMPONENT_INSTANCES + 1];
        let signatures = core::array::from_fn(|_| vec![Fr::ONE; 68]);
        let z = assignment(&joined, &core, &signatures).unwrap();
        assert_eq!(residual_failures(&joined, &z).unwrap(), 0);
        let mut wrong = signatures.clone();
        wrong[1][20] = Fr::from(2u64);
        let z = assignment(&joined, &core, &wrong).unwrap();
        assert!(residual_failures(&joined, &z).unwrap() > 0);
        let mut zero = core;
        zero[0] = Fr::ZERO;
        assert!(assignment(&joined, &zero, &signatures).is_err());
    }
    #[test]
    fn dropped_edge_prefix_and_invalid_columns_refuse() {
        let mut signatures = core::array::from_fn(|_| component(67));
        signatures[2] = component(66);
        assert!(matches!(
            join(&component(COMPONENT_INSTANCES), &signatures),
            Err(Boundary::Shape)
        ));
        signatures[2] = component(67);
        signatures[0].matrices[0][0][0].1 = usize::MAX;
        assert!(matches!(
            join(&component(COMPONENT_INSTANCES), &signatures),
            Err(Boundary::Column)
        ));
    }
}
