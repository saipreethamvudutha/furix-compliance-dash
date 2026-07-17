"use client";

export function NewScanDial({ label = "New\nScan", onClick }: { label?: string; onClick?: () => void }) {
  const TICK_COUNT = 36;
  const RADIUS = 44; // distance from dial center to tick (sits just inside the rim of a 100px dial)
  const LED_RADIUS = 40;
  const ticks = Array.from({ length: TICK_COUNT });
  const leds = [0, 90, 180, 270];

  return (
    <div className="dial-wrap">
      {/* Ticks layer — centered overlay */}
      <div
        className="pointer-events-none absolute inset-0"
        style={{ borderRadius: "50%" }}
      >
        {ticks.map((_, i) => {
          const angle = (i * 360) / TICK_COUNT;
          return (
            <span
              key={i}
              style={{
                position: "absolute",
                left: "50%",
                top: "50%",
                width: 1.5,
                height: 6,
                marginLeft: -0.75,
                marginTop: -3,
                background: "rgba(232,194,140,0.55)",
                borderRadius: 1,
                transform: `rotate(${angle}deg) translateY(-${RADIUS}px)`,
                transformOrigin: "center center",
              }}
            />
          );
        })}
        {leds.map((deg) => (
          <span
            key={deg}
            style={{
              position: "absolute",
              left: "50%",
              top: "50%",
              width: 5,
              height: 5,
              marginLeft: -2.5,
              marginTop: -2.5,
              borderRadius: "50%",
              background: "#6fd6c4",
              boxShadow:
                "0 0 8px #6fd6c4, 0 0 18px rgba(111,214,196,0.6)",
              transform: `rotate(${deg}deg) translateY(-${LED_RADIUS}px)`,
              transformOrigin: "center center",
            }}
          />
        ))}
      </div>

      <button onClick={onClick} className="dial-core text-[13px] leading-tight">
        {label.split("\n").map((s, i) => (
          <span key={i} className="block">
            {s}
          </span>
        ))}
      </button>
    </div>
  );
}
