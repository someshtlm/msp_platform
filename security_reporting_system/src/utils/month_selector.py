from datetime import datetime, timedelta
from typing import List, Dict, Tuple
from dataclasses import dataclass


@dataclass
class MonthInfo:
    """Information about a specific month for reporting"""
    month_name: str
    month_number: int
    year: int
    start_timestamp: float
    end_timestamp: float
    display_name: str


class MonthSelector:
    """Utility class for handling month selection and timestamp calculations"""

    def __init__(self):
        self.month_names = [
            "January", "February", "March", "April", "May", "June",
            "July", "August", "September", "October", "November", "December"
        ]

    def get_available_months(self, count: int = 3) -> List[MonthInfo]:
        """
        Get the last N months (excluding current month) for report generation

        Args:
            count: Number of previous months to return (default: 3)

        Returns:
            List of MonthInfo objects for the last N months
        """
        months = []
        today = datetime.now()

        for i in range(1, count + 1):
            # Calculate the target month by going back i months
            target_date = today.replace(day=1) - timedelta(days=1)
            for _ in range(i - 1):
                target_date = target_date.replace(day=1) - timedelta(days=1)

            # Get first and last day of the target month
            first_day = target_date.replace(day=1)
            if target_date.month == 12:
                last_day = target_date.replace(year=target_date.year + 1, month=1, day=1) - timedelta(days=1)
            else:
                last_day = target_date.replace(month=target_date.month + 1, day=1) - timedelta(days=1)

            # Create timestamps (start of day for first day, end of day for last day)
            start_timestamp = first_day.timestamp()
            end_timestamp = (last_day.replace(hour=23, minute=59, second=59)).timestamp()

            month_info = MonthInfo(
                month_name=self.month_names[target_date.month - 1],
                month_number=target_date.month,
                year=target_date.year,
                start_timestamp=start_timestamp,
                end_timestamp=end_timestamp,
                display_name=f"{self.month_names[target_date.month - 1]} {target_date.year}"
            )
            months.append(month_info)

        return months

    def get_month_by_name(self, month_name: str) -> MonthInfo:
        """
        Get month information by month name (e.g., "August", "July")

        Args:
            month_name: Name of the month to get info for

        Returns:
            MonthInfo object for the specified month

        Raises:
            ValueError: If month name is not found in available months
        """
        available_months = self.get_available_months()

        for month in available_months:
            if month.month_name.lower() == month_name.lower():
                return month

        available_names = [m.month_name for m in available_months]
        raise ValueError(f"Month '{month_name}' not found. Available months: {available_names}")

    def get_month_timestamps(self, month_name: str = None) -> Tuple[float, float]:
        """
        Get start and end timestamps for a specific month or default to previous month

        Args:
            month_name: Name of the month (optional, defaults to previous month)

        Returns:
            Tuple of (start_timestamp, end_timestamp)
        """
        if month_name:
            month_info = self.get_month_by_name(month_name)
            return month_info.start_timestamp, month_info.end_timestamp
        else:
            # Default to previous month (backward compatibility)
            available_months = self.get_available_months(count=1)
            if available_months:
                return available_months[0].start_timestamp, available_months[0].end_timestamp
            else:
                raise ValueError("No available months found")

    def list_available_months(self) -> List[Dict[str, str]]:
        """
        Get a simple list of available months for API responses

        Returns:
            List of dictionaries with month information
        """
        months = self.get_available_months()
        return [
            {
                "name": month.month_name,
                "display_name": month.display_name,
                "year": str(month.year),
                "month_number": str(month.month_number)
            }
            for month in months
        ]