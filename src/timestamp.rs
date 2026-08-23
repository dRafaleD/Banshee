use anyhow::{Context, Result, bail};
use clap::ValueEnum;
use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum TimestampUnit {
    Auto,
    Seconds,
    Milliseconds,
    Microseconds,
    Nanoseconds,
}

impl std::fmt::Display for TimestampUnit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Auto => "auto",
            Self::Seconds => "seconds",
            Self::Milliseconds => "milliseconds",
            Self::Microseconds => "microseconds",
            Self::Nanoseconds => "nanoseconds",
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct HumanTimestampReport {
    pub input: i128,
    pub detected_unit: TimestampUnit,
    pub utc: String,
    pub unix_seconds: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct UnixTimestampReport {
    pub input: String,
    pub unit: TimestampUnit,
    pub value: i128,
}

pub fn to_human(value: i128, unit: TimestampUnit) -> Result<HumanTimestampReport> {
    let detected_unit = if unit == TimestampUnit::Auto {
        infer_unit(value)
    } else {
        unit
    };
    let nanos = match detected_unit {
        TimestampUnit::Auto => unreachable!("auto is resolved above"),
        TimestampUnit::Seconds => value.checked_mul(1_000_000_000),
        TimestampUnit::Milliseconds => value.checked_mul(1_000_000),
        TimestampUnit::Microseconds => value.checked_mul(1_000),
        TimestampUnit::Nanoseconds => Some(value),
    }
    .context("timestamp overflow while converting to nanoseconds")?;
    let datetime = OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .context("timestamp is outside the supported date range")?;

    Ok(HumanTimestampReport {
        input: value,
        detected_unit,
        utc: datetime
            .format(&Rfc3339)
            .context("failed to format timestamp")?,
        unix_seconds: datetime.unix_timestamp(),
    })
}

pub fn to_unix(value: &str, unit: TimestampUnit) -> Result<UnixTimestampReport> {
    if unit == TimestampUnit::Auto {
        bail!("auto is only valid for timestamp to-human");
    }
    let datetime = OffsetDateTime::parse(value, &Rfc3339)
        .context("invalid RFC3339 date-time; expected a value like 2024-01-01T00:00:00Z")?;
    let nanos = datetime.unix_timestamp_nanos();
    let output = match unit {
        TimestampUnit::Auto => unreachable!(),
        TimestampUnit::Seconds => i128::from(datetime.unix_timestamp()),
        TimestampUnit::Milliseconds => nanos.div_euclid(1_000_000),
        TimestampUnit::Microseconds => nanos.div_euclid(1_000),
        TimestampUnit::Nanoseconds => nanos,
    };

    Ok(UnixTimestampReport {
        input: value.to_owned(),
        unit,
        value: output,
    })
}

fn infer_unit(value: i128) -> TimestampUnit {
    let magnitude = value.unsigned_abs();
    if magnitude >= 100_000_000_000_000_000 {
        TimestampUnit::Nanoseconds
    } else if magnitude >= 100_000_000_000_000 {
        TimestampUnit::Microseconds
    } else if magnitude >= 100_000_000_000 {
        TimestampUnit::Milliseconds
    } else {
        TimestampUnit::Seconds
    }
}

#[cfg(test)]
mod tests {
    use super::{TimestampUnit, to_human, to_unix};

    #[test]
    fn converts_epoch_to_utc() {
        let report = to_human(0, TimestampUnit::Seconds).expect("valid timestamp");
        assert_eq!(report.utc, "1970-01-01T00:00:00Z");
    }

    #[test]
    fn infers_milliseconds() {
        let report = to_human(1_704_067_200_000, TimestampUnit::Auto).expect("valid timestamp");
        assert_eq!(report.detected_unit, TimestampUnit::Milliseconds);
        assert_eq!(report.utc, "2024-01-01T00:00:00Z");
    }

    #[test]
    fn converts_rfc3339_to_unix() {
        let report =
            to_unix("2024-01-01T00:00:00Z", TimestampUnit::Seconds).expect("valid RFC3339");
        assert_eq!(report.value, 1_704_067_200);
    }
}
